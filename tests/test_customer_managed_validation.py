# SPDX-License-Identifier: MIT
"""Tests for source/validation/customer-managed-validation.py."""

import json

import pytest


# --------------------------------------------------------------------------- #
# load_policy_files
# --------------------------------------------------------------------------- #


def test_load_policy_files_loads_valid_jsons(validation_module, tmp_path):
    """Every *.json file in the folder is parsed and indexed by filename."""
    (tmp_path / "policy_a.json").write_text(json.dumps({"PolicyName": "A"}))
    (tmp_path / "policy_b.json").write_text(json.dumps({"PolicyName": "B"}))

    result = validation_module.load_policy_files(str(tmp_path))

    assert set(result.keys()) == {"policy_a.json", "policy_b.json"}
    assert result["policy_a.json"]["PolicyName"] == "A"


def test_load_policy_files_skips_non_json(validation_module, tmp_path):
    """Files that don't end with .json are ignored."""
    (tmp_path / "policy.json").write_text(json.dumps({"PolicyName": "A"}))
    (tmp_path / "README.md").write_text("not a policy")
    (tmp_path / "policy.txt").write_text("also not a policy")

    result = validation_module.load_policy_files(str(tmp_path))

    assert list(result.keys()) == ["policy.json"]


def test_load_policy_files_returns_empty_for_missing_folder(validation_module, tmp_path):
    """Non-existent folder returns {} and logs a warning, but does not raise."""
    missing = tmp_path / "does-not-exist"

    result = validation_module.load_policy_files(str(missing))

    assert result == {}


def test_load_policy_files_raises_on_invalid_json(validation_module, tmp_path):
    """Malformed JSON propagates as JSONDecodeError so the pipeline fails."""
    (tmp_path / "broken.json").write_text("{ not valid json")

    with pytest.raises(json.JSONDecodeError):
        validation_module.load_policy_files(str(tmp_path))


# --------------------------------------------------------------------------- #
# validate_unique_policy_name
# --------------------------------------------------------------------------- #


def test_validate_unique_policy_name_passes_when_unique(validation_module):
    policies = {
        "p1.json": {"PolicyName": "A"},
        "p2.json": {"PolicyName": "B"},
        "p3.json": {"PolicyName": "C"},
    }
    # Should not raise.
    validation_module.validate_unique_policy_name(policies)


def test_validate_unique_policy_name_raises_on_duplicates(validation_module):
    policies = {
        "p1.json": {"PolicyName": "A"},
        "p2.json": {"PolicyName": "A"},  # duplicate
        "p3.json": {"PolicyName": "C"},
    }
    with pytest.raises(ValueError, match="Duplicate PolicyName"):
        validation_module.validate_unique_policy_name(policies)


def test_validate_unique_policy_name_raises_on_empty(validation_module):
    with pytest.raises(ValueError, match="No policy files"):
        validation_module.validate_unique_policy_name({})


def test_validate_unique_policy_name_ignores_entries_without_policy_name(validation_module):
    """Entries lacking PolicyName are silently skipped (caller did its job upstream)."""
    policies = {
        "p1.json": {"PolicyName": "A"},
        "broken.json": {"NotAPolicy": True},  # no PolicyName key
    }
    # Should not raise.
    validation_module.validate_unique_policy_name(policies)


# --------------------------------------------------------------------------- #
# validate_policy_paths
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", ["/", "/admin/", "/customer1/", "/foo/bar/", "/a/b/c/"])
def test_validate_policy_paths_accepts_valid_paths(validation_module, path):
    """Each valid IAM-style path passes without raising."""
    policies = {"p.json": {"PolicyName": "P", "Path": path}}
    validation_module.validate_policy_paths(policies)


def test_validate_policy_paths_defaults_to_slash_when_missing(validation_module):
    """A missing Path is treated as '/' (IAM default) — no error."""
    policies = {"p.json": {"PolicyName": "P"}}  # no Path key
    validation_module.validate_policy_paths(policies)


@pytest.mark.parametrize(
    "bad_path,reason",
    [
        ("admin/", "no leading slash"),
        ("/admin", "no trailing slash"),
        ("//", "empty segment"),
        ("/foo//bar/", "empty segment in the middle"),
        ("/foo bar/", "space in segment"),
        ("/foo<>/", "disallowed chars"),
        ("", "empty string"),
    ],
)
def test_validate_policy_paths_rejects_invalid_paths(validation_module, bad_path, reason):
    """Each invalid Path raises ValueError with a useful message (reason: %s)."""
    policies = {"bad.json": {"PolicyName": "P", "Path": bad_path}}
    with pytest.raises(ValueError, match="Invalid Path"):
        validation_module.validate_policy_paths(policies)


def test_validate_policy_paths_rejects_non_string_path(validation_module):
    """Non-string Path (e.g., a list or dict by mistake) is reported clearly."""
    policies = {"p.json": {"PolicyName": "P", "Path": ["/admin/"]}}
    with pytest.raises(ValueError, match="Invalid Path"):
        validation_module.validate_policy_paths(policies)


def test_validate_policy_paths_rejects_path_over_max_length(validation_module):
    """Paths longer than IAM's 512-char limit are rejected locally."""
    too_long = "/" + "a" * 600 + "/"
    policies = {"p.json": {"PolicyName": "P", "Path": too_long}}
    with pytest.raises(ValueError, match="Invalid Path"):
        validation_module.validate_policy_paths(policies)


def test_validate_policy_paths_aggregates_multiple_errors(validation_module, caplog):
    """All bad entries are logged before raising — the operator sees them at once."""
    import logging
    caplog.set_level(logging.ERROR)

    policies = {
        "ok.json": {"PolicyName": "Ok", "Path": "/"},
        "bad1.json": {"PolicyName": "B1", "Path": "//"},
        "bad2.json": {"PolicyName": "B2", "Path": "/no-trailing-slash"},
    }
    with pytest.raises(ValueError, match="2 policy template"):
        validation_module.validate_policy_paths(policies)

    assert "bad1.json" in caplog.text
    assert "bad2.json" in caplog.text
    assert "ok.json" not in caplog.text


def test_real_templates_have_valid_paths(validation_module, project_root):
    """Smoke test: all actual templates have valid Path values."""
    folder = project_root / "templates" / "customer-managed-policies"
    policies = validation_module.load_policy_files(str(folder))
    validation_module.validate_policy_paths(policies)


# --------------------------------------------------------------------------- #
# load_assignment_files
# --------------------------------------------------------------------------- #


def test_load_assignment_files_loads_valid_jsons(validation_module, tmp_path):
    """Every *.json file in the folder is parsed and indexed by filename."""
    (tmp_path / "a.json").write_text(json.dumps({"Assignments": []}))
    (tmp_path / "b.json").write_text(json.dumps({"Assignments": [{"SID": "X"}]}))

    result = validation_module.load_assignment_files(str(tmp_path))

    assert set(result.keys()) == {"a.json", "b.json"}
    assert result["b.json"]["Assignments"][0]["SID"] == "X"


def test_load_assignment_files_skips_non_json(validation_module, tmp_path):
    (tmp_path / "real.json").write_text(json.dumps({"Assignments": []}))
    (tmp_path / "ignored.txt").write_text("not json")

    result = validation_module.load_assignment_files(str(tmp_path))
    assert list(result.keys()) == ["real.json"]


def test_load_assignment_files_returns_empty_for_missing_folder(validation_module, tmp_path):
    """Missing folder returns {} and warns — does not raise."""
    result = validation_module.load_assignment_files(str(tmp_path / "nope"))
    assert result == {}


def test_load_assignment_files_raises_on_invalid_json(validation_module, tmp_path):
    (tmp_path / "broken.json").write_text("{ not valid")
    with pytest.raises(json.JSONDecodeError):
        validation_module.load_assignment_files(str(tmp_path))


# --------------------------------------------------------------------------- #
# validate_target_account_ids
# --------------------------------------------------------------------------- #


def test_validate_target_account_ids_accepts_valid(validation_module):
    """A canonical assignment with 12-digit IDs passes."""
    assignments = {
        "a.json": {
            "Assignments": [
                {"SID": "X", "Target": ["111111111111", "222222222222"]},
                {"SID": "Y", "Target": ["444444444444"]},
            ],
        },
    }
    validation_module.validate_target_account_ids(assignments)


def test_validate_target_account_ids_handles_missing_assignments_key(validation_module):
    """A JSON without 'Assignments' key contributes 0 errors (no crash)."""
    validation_module.validate_target_account_ids({"empty.json": {}})


def test_validate_target_account_ids_handles_empty_target_list(validation_module):
    """An assignment with empty Target [] is allowed (no IDs to validate)."""
    validation_module.validate_target_account_ids({
        "a.json": {"Assignments": [{"SID": "X", "Target": []}]},
    })


@pytest.mark.parametrize(
    "bad_id,reason",
    [
        ("123", "fewer than 12 digits"),
        ("99999999999", "11 digits"),
        ("1234567890123", "13 digits"),
        ("abc123456789", "contains letters"),
        ("111111111111 ", "trailing whitespace"),
        (" 111111111111", "leading whitespace"),
        ("873-948-628-122", "dashes"),
        ("873,948,628,122", "commas"),
        ("", "empty string"),
    ],
)
def test_validate_target_account_ids_rejects_invalid(validation_module, bad_id, reason):
    """Each invalid ID raises ValueError with a useful message (reason: %s)."""
    assignments = {
        "a.json": {"Assignments": [{"SID": "X", "Target": [bad_id]}]},
    }
    with pytest.raises(ValueError, match="Invalid Target account ID"):
        validation_module.validate_target_account_ids(assignments)


def test_validate_target_account_ids_rejects_non_string(validation_module, caplog):
    """Numbers, booleans, lists are rejected — the JSON should declare strings."""
    import logging
    caplog.set_level(logging.ERROR)

    assignments = {
        "a.json": {
            "Assignments": [{"SID": "X", "Target": [111111111111]}],  # int, not str
        },
    }
    with pytest.raises(ValueError, match="Invalid Target account ID"):
        validation_module.validate_target_account_ids(assignments)

    # The specific reason is logged before the aggregated raise.
    assert "must be a string" in caplog.text


def test_validate_target_account_ids_rejects_target_not_a_list(validation_module, caplog):
    """Target accidentally typed as a string instead of [string] is reported."""
    import logging
    caplog.set_level(logging.ERROR)

    assignments = {
        "a.json": {
            "Assignments": [{"SID": "X", "Target": "111111111111"}],  # missing []
        },
    }
    with pytest.raises(ValueError, match="Invalid Target account ID"):
        validation_module.validate_target_account_ids(assignments)

    assert "Target must be a list" in caplog.text


def test_validate_target_account_ids_aggregates_errors(validation_module, caplog):
    """Multiple bad entries are all logged before raising."""
    import logging
    caplog.set_level(logging.ERROR)

    assignments = {
        "a.json": {
            "Assignments": [
                {"SID": "Good", "Target": ["111111111111"]},
                {"SID": "Bad1", "Target": ["123"]},
                {"SID": "Bad2", "Target": ["abc123456789", "111111111111 "]},
            ],
        },
    }
    with pytest.raises(ValueError, match="3 entry"):
        validation_module.validate_target_account_ids(assignments)

    assert "Bad1" in caplog.text
    assert "Bad2" in caplog.text
    assert "Good" not in caplog.text


def test_real_assignments_have_valid_target_ids(validation_module, project_root):
    """Smoke test: actual assignments folder has only 12-digit Target IDs."""
    folder = project_root / "templates" / "assignments"
    assignments = validation_module.load_assignment_files(str(folder))
    assert assignments, "No assignment files were found in templates/assignments/"
    validation_module.validate_target_account_ids(assignments)


# --------------------------------------------------------------------------- #
# Smoke test against the real templates folder
# --------------------------------------------------------------------------- #


def test_real_templates_have_unique_policy_names(validation_module, project_root):
    """Sanity check: the actual customer-managed-policies folder is consistent."""
    folder = project_root / "templates" / "customer-managed-policies"
    policies = validation_module.load_policy_files(str(folder))

    assert policies, "No policy templates were found in templates/customer-managed-policies/"
    validation_module.validate_unique_policy_name(policies)


# --------------------------------------------------------------------------- #
# validate_policy_documents
# --------------------------------------------------------------------------- #


def _mk(policy_document, name="P"):
    return {"p.json": {"PolicyName": name, "Path": "/", "PolicyDocument": policy_document}}


def test_validate_policy_documents_accepts_narrow_policy(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:DescribeInstances", "s3:GetObject"],
                "Resource": "*",
            }
        ],
    }
    validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_rejects_action_star(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_rejects_iam_wildcard(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_rejects_iam_passrole(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
        ],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_rejects_sts_wildcard(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:*", "Resource": "*"}],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_rejects_not_action(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
        ],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_rejects_not_resource(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::foo/*",
            }
        ],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_rejects_resource_star_sensitive(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}
        ],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_requires_policy_document(validation_module):
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents({"p.json": {"PolicyName": "P"}})


def test_validate_policy_documents_requires_version(validation_module):
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_rejects_malformed_action(validation_module):
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "not a valid action", "Resource": "*"}
        ],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_enforces_size_limit(validation_module):
    # Build a huge valid-ish document that exceeds 6144 chars.
    long_actions = [f"s3:Action{i:04d}" for i in range(1000)]
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": long_actions, "Resource": "*"}
        ],
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_accepts_deny_wildcard(validation_module):
    # Deny with service wildcards is useful (defensive) and not forbidden.
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["ec2:TerminateInstances"],
                "Resource": "*",
            }
        ],
    }
    validation_module.validate_policy_documents(_mk(doc))


def test_validate_policy_documents_aggregates_errors(validation_module, caplog):
    import logging
    caplog.set_level(logging.ERROR)
    policies = {
        "ok.json": {
            "PolicyName": "Ok",
            "Path": "/",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}
                ],
            },
        },
        "bad.json": {
            "PolicyName": "Bad",
            "Path": "/",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ],
            },
        },
    }
    with pytest.raises(ValueError, match="PolicyDocument validation failed"):
        validation_module.validate_policy_documents(policies)
    assert "bad.json" in caplog.text
    assert "ok.json" not in caplog.text


def test_real_templates_pass_policy_document_validation(validation_module, project_root):
    """Smoke test: shipped sample policies pass structural validation."""
    folder = project_root / "templates" / "customer-managed-policies"
    policies = validation_module.load_policy_files(str(folder))
    validation_module.validate_policy_documents(policies)


# --------------------------------------------------------------------------- #
# validate_policies_with_access_analyzer
# --------------------------------------------------------------------------- #


def test_access_analyzer_skip_flag_bypasses_call(validation_module):
    """When skip=True the function must not try to import boto3 or make calls."""
    # No ImportError should surface even if boto3 is unavailable; no exception.
    validation_module.validate_policies_with_access_analyzer(
        {"p.json": {"PolicyDocument": {"Version": "2012-10-17", "Statement": []}}},
        region="us-east-1",
        skip=True,
    )


def test_access_analyzer_fails_build_on_blocking_findings(validation_module, monkeypatch):
    """ERROR / SECURITY_WARNING findings raise ValueError and fail the build."""
    class _FakePaginator:
        def paginate(self, **_kw):
            return iter([{
                "findings": [
                    {"findingType": "SECURITY_WARNING", "issueCode": "PASS_ROLE_WITH_STAR_IN_RESOURCE", "findingDetails": "Allow PassRole with Resource *"},
                    {"findingType": "SUGGESTION", "issueCode": "REDUNDANT", "findingDetails": "minor"},
                ]
            }])

    class _FakeClient:
        def get_paginator(self, _name):
            return _FakePaginator()

    class _FakeBoto3:
        @staticmethod
        def client(_name, region_name=None):
            return _FakeClient()

    import sys as _sys
    monkeypatch.setitem(_sys.modules, "boto3", _FakeBoto3)

    # Provide a stub botocore.exceptions module so the import inside the
    # function finds BotoCoreError / ClientError without needing botocore.
    import types
    fake_botocore = types.ModuleType("botocore")
    fake_botocore_exc = types.ModuleType("botocore.exceptions")
    class _BotoCoreError(Exception):
        pass
    class _ClientError(Exception):
        pass
    fake_botocore_exc.BotoCoreError = _BotoCoreError
    fake_botocore_exc.ClientError = _ClientError
    monkeypatch.setitem(_sys.modules, "botocore", fake_botocore)
    monkeypatch.setitem(_sys.modules, "botocore.exceptions", fake_botocore_exc)

    policies = {
        "p.json": {
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                ],
            }
        }
    }
    with pytest.raises(ValueError, match="Access Analyzer"):
        validation_module.validate_policies_with_access_analyzer(
            policies, region="us-east-1", skip=False,
        )
