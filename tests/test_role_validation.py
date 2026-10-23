# SPDX-License-Identifier: MIT
"""Tests for source/validation/role-validation.py."""

import json

import boto3
import pytest
from moto import mock_aws


# --------------------------------------------------------------------------- #
# get_target_accounts — pure-function tests, no AWS
# --------------------------------------------------------------------------- #


def test_get_target_accounts_aggregates_from_all_files(role_validation_module, tmp_path):
    """Account IDs are taken from every assignment file in the folder."""
    (tmp_path / "a1.json").write_text(json.dumps({
        "Assignments": [
            {"Target": ["111111111111", "222222222222"], "CustomerManagedPolicyName": ["P1"]},
        ],
    }))
    (tmp_path / "a2.json").write_text(json.dumps({
        "Assignments": [
            {"Target": ["222222222222", "333333333333"], "CustomerManagedPolicyName": ["P2"]},
        ],
    }))

    accounts = role_validation_module.get_target_accounts(str(tmp_path))

    # Set semantics — duplicates collapsed.
    assert accounts == {"111111111111", "222222222222", "333333333333"}


def test_get_target_accounts_skips_non_json(role_validation_module, tmp_path):
    (tmp_path / "real.json").write_text(json.dumps({
        "Assignments": [{"Target": ["111111111111"], "CustomerManagedPolicyName": ["P1"]}],
    }))
    (tmp_path / "ignored.txt").write_text("not a JSON")

    accounts = role_validation_module.get_target_accounts(str(tmp_path))
    assert accounts == {"111111111111"}


def test_get_target_accounts_handles_missing_assignments_key(role_validation_module, tmp_path):
    """A JSON without 'Assignments' contributes 0 accounts (no crash)."""
    (tmp_path / "empty.json").write_text(json.dumps({}))
    accounts = role_validation_module.get_target_accounts(str(tmp_path))
    assert accounts == set()


def test_get_target_accounts_exits_when_folder_missing(role_validation_module, tmp_path):
    """Missing folder is a hard failure (sys.exit(1))."""
    with pytest.raises(SystemExit) as excinfo:
        role_validation_module.get_target_accounts(str(tmp_path / "no-such-dir"))
    assert excinfo.value.code == 1


def test_get_target_accounts_exits_on_invalid_account_id(role_validation_module, tmp_path):
    """Invalid Target IDs are detected and exit non-zero (defense in depth)."""
    (tmp_path / "a.json").write_text(json.dumps({
        "Assignments": [
            {"SID": "X", "Target": ["111111111111", "abc123"]},  # one invalid
        ],
    }))

    with pytest.raises(SystemExit) as excinfo:
        role_validation_module.get_target_accounts(str(tmp_path))
    assert excinfo.value.code == 1


def test_get_target_accounts_exits_on_account_id_with_whitespace(
    role_validation_module, tmp_path
):
    """Trailing whitespace in account ID also triggers the safety check."""
    (tmp_path / "a.json").write_text(json.dumps({
        "Assignments": [{"SID": "X", "Target": ["111111111111 "]}],
    }))

    with pytest.raises(SystemExit) as excinfo:
        role_validation_module.get_target_accounts(str(tmp_path))
    assert excinfo.value.code == 1


# --------------------------------------------------------------------------- #
# check_role_exists — exercised against moto
# --------------------------------------------------------------------------- #


@mock_aws
def test_check_role_exists_returns_true_when_role_present(
    role_validation_module, aws_credentials, monkeypatch
):
    """If the role exists, is assumable, and its trust policy carries the
    sts:ExternalId condition, the function returns True."""
    monkeypatch.setenv("EXTERNAL_ID", "test-external-id-1234567890")
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName=role_validation_module.ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "test-external-id-1234567890",
                    },
                },
            }],
        }),
    )

    # moto STS lets you assume any role ARN; with the role created it will succeed.
    assert role_validation_module.check_role_exists("123456789012") is True


@mock_aws
def test_check_role_exists_returns_false_when_role_missing(
    role_validation_module, aws_credentials, monkeypatch
):
    """If the role does not exist, the function returns False (doesn't raise)."""
    monkeypatch.setenv("EXTERNAL_ID", "test-external-id-1234567890")
    # No role created → assume_role/get_role should fail and the function returns False.
    assert role_validation_module.check_role_exists("123456789012") is False


# --------------------------------------------------------------------------- #
# _build_session_name helper (LOW-9 audit trail)
# --------------------------------------------------------------------------- #


def test_build_session_name_default_prefix_is_validate(role_validation_module, monkeypatch):
    """The role-validation script uses a distinct prefix from the deploy script."""
    monkeypatch.delenv("CODEBUILD_BUILD_ID", raising=False)
    name = role_validation_module._build_session_name()
    assert name.startswith("CxMngValidate-")


def test_build_session_name_uses_codebuild_id(role_validation_module, monkeypatch):
    """CODEBUILD_BUILD_ID is sanitized and appended to the prefix."""
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "proj:uuid-1234")
    name = role_validation_module._build_session_name("CxMngValidate")
    assert ":" not in name
    assert "uuid-1234" in name
    assert len(name) <= 64


# --------------------------------------------------------------------------- #
# Resilience tests (Gap 2)
# botocore.stub cannot trigger boto3's retry handler (it intercepts after the
# retry chain), so we only assert the config IS attached. Real retry behavior
# is exercised in integration / E2E.
# --------------------------------------------------------------------------- #


def test_role_validation_boto3_config_has_expected_settings(role_validation_module):
    """Role-validation script shares the same retry/timeout policy as deploy."""
    config = role_validation_module.BOTO3_CONFIG
    assert config.connect_timeout == 10
    assert config.read_timeout == 30
    assert config.retries.get("max_attempts") == 2
    assert config.retries.get("mode") == "adaptive"


# --- ExternalId behavior --- #


from unittest.mock import MagicMock, patch  # noqa: E402


def _make_sts_mock_returning_creds():
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIATEST",
            "SecretAccessKey": "secrettest",
            "SessionToken": "sessiontest",
        }
    }
    return sts


def _patch_boto3_clients(module, sts_mock, iam_mock):
    def fake_client(service_name, **_kwargs):
        if service_name == "sts":
            return sts_mock
        if service_name == "iam":
            return iam_mock
        raise AssertionError(f"Unexpected service: {service_name}")
    return patch.object(module.boto3, "client", side_effect=fake_client)


def test_check_role_exists_passes_external_id_when_env_var_set(
    role_validation_module, monkeypatch
):
    """When EXTERNAL_ID is set, check_role_exists threads it into assume_role."""
    monkeypatch.setenv("EXTERNAL_ID", "test-external-id-1234567890")

    sts_mock = _make_sts_mock_returning_creds()
    iam_mock = MagicMock()
    iam_mock.get_role.return_value = {
        "Role": {
            "RoleName": role_validation_module.ROLE_NAME,
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "test-external-id-1234567890",
                        },
                    },
                }],
            },
        },
    }

    with _patch_boto3_clients(role_validation_module, sts_mock, iam_mock):
        result = role_validation_module.check_role_exists("123456789012")

    assert result is True
    call_kwargs = sts_mock.assume_role.call_args.kwargs
    assert call_kwargs.get("ExternalId") == "test-external-id-1234567890"


def test_check_role_exists_fails_when_trust_policy_missing_external_id_condition(
    role_validation_module, monkeypatch
):
    """A role whose trust policy does NOT carry sts:ExternalId fails the stage,
    even if assume_role happened to succeed."""
    monkeypatch.setenv("EXTERNAL_ID", "test-external-id-1234567890")

    sts_mock = _make_sts_mock_returning_creds()
    iam_mock = MagicMock()
    iam_mock.get_role.return_value = {
        "Role": {
            "RoleName": role_validation_module.ROLE_NAME,
            # No Condition at all → defense-in-depth check must fail closed.
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "sts:AssumeRole",
                }],
            },
        },
    }

    with _patch_boto3_clients(role_validation_module, sts_mock, iam_mock):
        result = role_validation_module.check_role_exists("123456789012")

    assert result is False


def test_check_role_exists_fails_when_trust_policy_pins_wrong_external_id(
    role_validation_module, monkeypatch
):
    """A role whose trust policy pins a DIFFERENT ExternalId value fails."""
    monkeypatch.setenv("EXTERNAL_ID", "test-external-id-1234567890")

    sts_mock = _make_sts_mock_returning_creds()
    iam_mock = MagicMock()
    iam_mock.get_role.return_value = {
        "Role": {
            "RoleName": role_validation_module.ROLE_NAME,
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "a-completely-different-value-XYZ",
                        },
                    },
                }],
            },
        },
    }

    with _patch_boto3_clients(role_validation_module, sts_mock, iam_mock):
        result = role_validation_module.check_role_exists("123456789012")

    assert result is False


def test_load_external_id_exits_when_env_var_unset(
    role_validation_module, monkeypatch
):
    """EXTERNAL_ID is MANDATORY: unset → non-zero exit, no STS call."""
    monkeypatch.delenv("EXTERNAL_ID", raising=False)

    with pytest.raises(SystemExit) as excinfo:
        role_validation_module.load_external_id()
    assert excinfo.value.code == 1


def test_load_external_id_exits_when_env_var_empty(
    role_validation_module, monkeypatch
):
    """EXTERNAL_ID is MANDATORY: empty string → non-zero exit, no STS call."""
    monkeypatch.setenv("EXTERNAL_ID", "")

    with pytest.raises(SystemExit) as excinfo:
        role_validation_module.load_external_id()
    assert excinfo.value.code == 1


def test_load_external_id_exits_when_env_var_too_short(
    role_validation_module, monkeypatch
):
    """EXTERNAL_ID must match ^[A-Za-z0-9_-]{16,64}$ — too short fails closed."""
    monkeypatch.setenv("EXTERNAL_ID", "short")

    with pytest.raises(SystemExit) as excinfo:
        role_validation_module.load_external_id()
    assert excinfo.value.code == 1


def test_load_external_id_exits_when_env_var_has_bad_chars(
    role_validation_module, monkeypatch
):
    """EXTERNAL_ID must match ^[A-Za-z0-9_-]{16,64}$ — disallowed chars fail closed."""
    monkeypatch.setenv("EXTERNAL_ID", "has spaces and $pecial chars!!")

    with pytest.raises(SystemExit) as excinfo:
        role_validation_module.load_external_id()
    assert excinfo.value.code == 1


def test_check_role_exists_aborts_when_env_var_unset(
    role_validation_module, monkeypatch
):
    """When EXTERNAL_ID is absent, check_role_exists exits before any STS call."""
    monkeypatch.delenv("EXTERNAL_ID", raising=False)

    sts_mock = _make_sts_mock_returning_creds()
    iam_mock = MagicMock()

    with _patch_boto3_clients(role_validation_module, sts_mock, iam_mock):
        with pytest.raises(SystemExit) as excinfo:
            role_validation_module.check_role_exists("123456789012")

    assert excinfo.value.code == 1
    sts_mock.assume_role.assert_not_called()


def test_check_role_exists_aborts_when_env_var_empty(
    role_validation_module, monkeypatch
):
    """An empty EXTERNAL_ID is still a hard failure — no STS call issued."""
    monkeypatch.setenv("EXTERNAL_ID", "")

    sts_mock = _make_sts_mock_returning_creds()
    iam_mock = MagicMock()

    with _patch_boto3_clients(role_validation_module, sts_mock, iam_mock):
        with pytest.raises(SystemExit) as excinfo:
            role_validation_module.check_role_exists("123456789012")

    assert excinfo.value.code == 1
    sts_mock.assume_role.assert_not_called()
