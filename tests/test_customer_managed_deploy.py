# SPDX-License-Identifier: MIT
"""Tests for source/customer-managed-policies/customer-managed-deploy.py.

Focuses on pure helpers (hashing, tag filtering, diff) and on the S3 state
read/write/list contract using moto.
"""

import json

import boto3
import pytest
from moto import mock_aws


# --------------------------------------------------------------------------- #
# policy_hash
# --------------------------------------------------------------------------- #


def test_policy_hash_is_deterministic(deploy_module):
    """Same document always hashes to the same value."""
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*"}]}
    assert deploy_module.policy_hash(doc) == deploy_module.policy_hash(doc)


def test_policy_hash_is_key_order_independent(deploy_module):
    """Reordering keys in the document does not change the hash (sort_keys=True)."""
    doc1 = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*"}]}
    doc2 = {"Statement": [{"Action": "*", "Effect": "Allow"}], "Version": "2012-10-17"}
    assert deploy_module.policy_hash(doc1) == deploy_module.policy_hash(doc2)


def test_policy_hash_changes_when_document_changes(deploy_module):
    """A change in the policy document produces a different hash."""
    doc1 = {"Version": "2012-10-17", "Statement": [{"Action": "s3:GetObject"}]}
    doc2 = {"Version": "2012-10-17", "Statement": [{"Action": "s3:PutObject"}]}
    assert deploy_module.policy_hash(doc1) != deploy_module.policy_hash(doc2)


# --------------------------------------------------------------------------- #
# filter_tags
# --------------------------------------------------------------------------- #


def test_filter_tags_keeps_complete_entries(deploy_module):
    tags = [{"Key": "Owner", "Value": "team-x"}, {"Key": "cost-center", "Value": "1234"}]
    assert deploy_module.filter_tags(tags) == tags


def test_filter_tags_drops_entries_without_value(deploy_module):
    tags = [{"Key": "Owner", "Value": "team-x"}, {"Key": "Empty", "Value": ""}]
    assert deploy_module.filter_tags(tags) == [{"Key": "Owner", "Value": "team-x"}]


def test_filter_tags_drops_entries_without_key(deploy_module):
    tags = [{"Key": "", "Value": "x"}, {"Key": "Owner", "Value": "team-x"}]
    assert deploy_module.filter_tags(tags) == [{"Key": "Owner", "Value": "team-x"}]


def test_filter_tags_handles_empty_input(deploy_module):
    assert deploy_module.filter_tags([]) == []


# --------------------------------------------------------------------------- #
# diff_policy — verifies it does not blow up on edge cases
# --------------------------------------------------------------------------- #


def test_diff_policy_handles_identical_documents(deploy_module, caplog):
    doc = {"Version": "2012-10-17", "Statement": [{"Sid": "A", "Action": ["s3:GetObject"]}]}
    deploy_module.diff_policy("111111111111", "PolicyA", doc, doc)
    # Identical → early return, no DIFF log line.
    assert "DIFF" not in caplog.text


def test_diff_policy_handles_string_resource(deploy_module, caplog):
    """diff_policy must not crash when 'Resource' is a string (not a list)."""
    old = {"Statement": [{"Sid": "A", "Action": [], "Resource": "arn:aws:s3:::a"}]}
    new = {"Statement": [{"Sid": "A", "Action": [], "Resource": "arn:aws:s3:::b"}]}
    # Should run without raising.
    deploy_module.diff_policy("111111111111", "PolicyA", old, new)


def test_diff_policy_reports_added_and_removed_actions(deploy_module, caplog):
    import logging
    caplog.set_level(logging.INFO)

    old = {"Statement": [{"Sid": "A", "Action": ["s3:GetObject"]}]}
    new = {"Statement": [{"Sid": "A", "Action": ["s3:GetObject", "s3:PutObject"]}]}
    deploy_module.diff_policy("111111111111", "PolicyA", old, new)

    assert "Actions added" in caplog.text
    assert "s3:PutObject" in caplog.text


# --------------------------------------------------------------------------- #
# load_state / save_state — S3 round-trip via moto
# --------------------------------------------------------------------------- #


@mock_aws
def test_load_state_returns_empty_when_no_object(deploy_module, aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="state-bucket")
    assert deploy_module.load_state(s3, "111111111111", "state-bucket") == {}


@mock_aws
def test_load_state_returns_dict_when_object_exists(deploy_module, aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="state-bucket")
    payload = {"account_id": "111111111111", "policies": {"P1": {"policy_hash": "abc"}}}
    s3.put_object(
        Bucket="state-bucket",
        Key="state/111111111111.json",
        Body=json.dumps(payload),
    )

    assert deploy_module.load_state(s3, "111111111111", "state-bucket") == payload


@mock_aws
def test_load_state_returns_empty_when_bucket_unset(deploy_module, aws_credentials):
    """Without a state-bucket configured, load_state() returns {} without calling S3."""
    s3 = boto3.client("s3", region_name="us-east-1")  # not used
    assert deploy_module.load_state(s3, "111111111111", state_bucket=None) == {}


@mock_aws
def test_save_state_writes_and_stamps_timestamp(deploy_module, aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="state-bucket")
    state = {"account_id": "111111111111", "policies": {}}

    deploy_module.save_state(s3, "111111111111", state, "state-bucket")

    obj = s3.get_object(Bucket="state-bucket", Key="state/111111111111.json")
    written = json.loads(obj["Body"].read())
    assert written["account_id"] == "111111111111"
    assert "last_execution" in written  # save_state adds the UTC timestamp


# --------------------------------------------------------------------------- #
# get_previously_managed_accounts — listing under state/
# --------------------------------------------------------------------------- #


@mock_aws
def test_previously_managed_accounts_lists_existing_state_files(deploy_module, aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="state-bucket")
    s3.put_object(Bucket="state-bucket", Key="state/111111111111.json", Body=b"{}")
    s3.put_object(Bucket="state-bucket", Key="state/222222222222.json", Body=b"{}")
    # Should be ignored: file under a different prefix or not all-digits.
    s3.put_object(Bucket="state-bucket", Key="state/not-a-number.json", Body=b"{}")
    s3.put_object(Bucket="state-bucket", Key="other/333333333333.json", Body=b"{}")

    accounts = deploy_module.get_previously_managed_accounts(s3, "state-bucket")
    assert accounts == {"111111111111", "222222222222"}


@mock_aws
def test_previously_managed_accounts_empty_when_no_bucket(deploy_module, aws_credentials):
    """No bucket configured → return empty set, no S3 calls."""
    assert deploy_module.get_previously_managed_accounts(None, None) == set()


# --------------------------------------------------------------------------- #
# CLI args — defaults and overrides for assignments/policies folders
# --------------------------------------------------------------------------- #


def test_default_assignments_and_policies_folders_match_constants(deploy_module, monkeypatch):
    """When no override is given, parse_args() returns the documented defaults."""
    monkeypatch.setattr("sys.argv", ["customer-managed-deploy.py"])
    args = deploy_module.parse_args()
    assert args.assignments_folder == deploy_module.DEFAULT_ASSIGNMENTS_DIR
    assert args.policies_folder == deploy_module.DEFAULT_POLICIES_DIR
    assert args.dry_run is False
    assert args.state_bucket is None


def test_assignments_and_policies_folders_can_be_overridden(deploy_module, monkeypatch, tmp_path):
    """The CLI args take precedence over the defaults."""
    fake_assign = tmp_path / "a"
    fake_pol = tmp_path / "p"
    monkeypatch.setattr(
        "sys.argv",
        [
            "customer-managed-deploy.py",
            "--assignments-folder", str(fake_assign),
            "--policies-folder", str(fake_pol),
            "--dry-run",
        ],
    )
    args = deploy_module.parse_args()
    assert args.assignments_folder == str(fake_assign)
    assert args.policies_folder == str(fake_pol)
    assert args.dry_run is True


# --------------------------------------------------------------------------- #
# _validate_account_id helper (defense in depth)
# --------------------------------------------------------------------------- #


def test_validate_account_id_accepts_12_digits(deploy_module):
    """A canonical 12-digit string passes."""
    deploy_module._validate_account_id("111111111111", context="test")


@pytest.mark.parametrize(
    "bad",
    ["123", "99999999999", "1234567890123", "abc123456789", "111111111111 ", "", " 111111111111"],
)
def test_validate_account_id_rejects_invalid(deploy_module, bad):
    """Invalid IDs raise ValueError including the offending value and context."""
    with pytest.raises(ValueError, match="Invalid Target account ID"):
        deploy_module._validate_account_id(bad, context="assignments.json#X")


def test_validate_account_id_rejects_non_string(deploy_module):
    """Non-string values (int, dict, etc.) are rejected."""
    with pytest.raises(ValueError, match="Invalid Target account ID"):
        deploy_module._validate_account_id(111111111111, context="test")


def test_validate_account_id_includes_context_in_error(deploy_module):
    """The error message contains the supplied context for traceability."""
    with pytest.raises(ValueError, match="some-file.json#MyAssignment"):
        deploy_module._validate_account_id(
            "bad", context="some-file.json#MyAssignment"
        )


# --------------------------------------------------------------------------- #
# _build_session_name helper (LOW-9 audit trail)
# --------------------------------------------------------------------------- #


import re as _re  # for the IAM RoleSessionName regex check
IAM_SESSION_NAME_PATTERN = _re.compile(r"^[\w+=,.@-]{2,64}$")


def test_build_session_name_uses_codebuild_id_when_set(deploy_module, monkeypatch):
    """When CODEBUILD_BUILD_ID is set, it appears in the session name."""
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "myproj:abc12345-1234-1234-1234-1234567890ab")
    name = deploy_module._build_session_name("CxMngDeploy")
    assert name.startswith("CxMngDeploy-")
    # Colon must have been sanitized.
    assert ":" not in name
    # Both prefix and (sanitized) build_id parts are present.
    assert "myproj" in name
    assert "1234567890ab" in name


def test_build_session_name_falls_back_to_local(deploy_module, monkeypatch):
    """Without CODEBUILD_BUILD_ID env var, the suffix is 'local'."""
    monkeypatch.delenv("CODEBUILD_BUILD_ID", raising=False)
    name = deploy_module._build_session_name("CxMngDeploy")
    assert name == "CxMngDeploy-local"


def test_build_session_name_sanitizes_disallowed_chars(deploy_module, monkeypatch):
    """Colons, slashes and other disallowed chars are replaced with '-'."""
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "p:r/oj:ect")
    name = deploy_module._build_session_name("CxMngDeploy")
    assert ":" not in name
    assert "/" not in name


def test_build_session_name_respects_iam_64_char_limit(deploy_module, monkeypatch):
    """Even with a very long CODEBUILD_BUILD_ID, the result fits IAM's limit."""
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "a" * 200 + ":" + "b" * 200)
    name = deploy_module._build_session_name("CxMngDeploy")
    assert 2 <= len(name) <= 64


def test_build_session_name_keeps_unique_suffix_when_truncated(deploy_module, monkeypatch):
    """When truncation happens, we keep the *end* of the build_id (the unique UUID)."""
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "x" * 100 + "UNIQUE-TAIL-12345")
    name = deploy_module._build_session_name("CxMngDeploy")
    # The unique tail must survive truncation.
    assert "UNIQUE-TAIL-12345" in name


def test_build_session_name_no_double_hyphen_at_join(deploy_module, monkeypatch):
    """No 'PREFIX--suffix' artifact when truncation lands on a hyphen."""
    # Build ID where the truncation point falls on a sanitized colon.
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "iam-cx-mng-pipeline:abc12345-1234-5678-9012-1234567890ab")
    name = deploy_module._build_session_name("CxMngValidate")  # longer prefix forces truncation
    assert "--" not in name


def test_build_session_name_matches_iam_regex(deploy_module, monkeypatch):
    """The result is always a valid RoleSessionName per the IAM regex."""
    for build_id in [
        "local",
        "myproj:abc-def",
        "weird:chars/with(parens)and[brackets]",
        "x" * 200,
    ]:
        monkeypatch.setenv("CODEBUILD_BUILD_ID", build_id)
        name = deploy_module._build_session_name("CxMngDeploy")
        assert IAM_SESSION_NAME_PATTERN.match(name), (
            f"Generated session name {name!r} does not match IAM regex"
        )


# --------------------------------------------------------------------------- #
# Orchestration tests (Gap 1)
#
# These tests exercise the two main orchestration functions end-to-end against
# a moto-mocked AWS:
#   * create_update_customer_managed_policy()
#   * delete_customer_managed_policy()
# Plus the cross-account helpers get_iam_client() and get_current_policy_doc().
#
# Limitations of moto these tests do NOT catch:
#   * Real IAM permission evaluation (moto accepts any call regardless of perms)
#   * Throttling / quotas (5 policy versions limit, etc.)
#   * Eventual consistency (moto is always synchronous)
#   * Cross-account isolation differences from production
# See tests/README.md for the full coverage analysis.
# --------------------------------------------------------------------------- #


import argparse  # noqa: E402 - intentional late import for orchestration tests


# All target accounts in tests use moto's default account ID — moto routes
# assume_role-into-self correctly without needing real cross-account setup.
DEFAULT_ACCOUNT = "123456789012"

# A minimal but valid IAM policy document used as a baseline in tests.
DEFAULT_POLICY_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "T", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    ],
}


def _create_deploy_role(role_name: str = "deploy-customer-managed-policy"):
    """Create the cross-account deploy role in moto's IAM so assume_role works."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }),
    )


def _write_assignment(folder, *, sid: str, target: list, policies: list):
    """Write a single assignment JSON file into ``folder``."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "assignments.json").write_text(json.dumps({
        "Assignments": [
            {
                "SID": sid,
                "Target": target,
                "CustomerManagedPolicyName": policies,
            }
        ]
    }))
    return str(folder)


def _write_policy(folder, *, name: str, doc: dict = None, path: str = "/", tags: list = None):
    """Write a single policy template JSON file into ``folder``."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.json").write_text(json.dumps({
        "PolicyName": name,
        "Description": "test policy",
        "Path": path,
        "PolicyDocument": doc or DEFAULT_POLICY_DOC,
        "Tags": tags or [],
    }))
    return str(folder)


def _build_args(*, assignments_folder, policies_folder, dry_run=False, state_bucket=None):
    """Construct the argparse.Namespace the orchestrators expect."""
    return argparse.Namespace(
        dry_run=dry_run,
        state_bucket=state_bucket,
        assignments_folder=assignments_folder,
        policies_folder=policies_folder,
    )


# --------------------------------------------------------------------------- #
# get_iam_client
# --------------------------------------------------------------------------- #


@mock_aws
def test_get_iam_client_returns_working_iam_client(deploy_module, aws_credentials):
    """The helper assumes the cross-account role and returns a usable IAM client."""
    _create_deploy_role()

    iam = deploy_module.get_iam_client(DEFAULT_ACCOUNT)
    # If the client is functional, list_policies should not raise.
    response = iam.list_policies(Scope="Local")
    assert "Policies" in response


# --------------------------------------------------------------------------- #
# get_current_policy_doc
# --------------------------------------------------------------------------- #


@mock_aws
def test_get_current_policy_doc_returns_document_when_policy_exists(
    deploy_module, aws_credentials
):
    """For an existing policy, the helper returns the default version's document."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")
    response = iam.create_policy(
        PolicyName="ExistingPolicy",
        PolicyDocument=json.dumps(DEFAULT_POLICY_DOC),
    )
    policy_arn = response["Policy"]["Arn"]

    doc = deploy_module.get_current_policy_doc(iam, policy_arn)
    assert doc == DEFAULT_POLICY_DOC


@mock_aws
def test_get_current_policy_doc_returns_none_when_policy_missing(
    deploy_module, aws_credentials
):
    """When the policy ARN doesn't exist, the helper returns None (does not raise)."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    doc = deploy_module.get_current_policy_doc(
        iam, f"arn:aws:iam::{DEFAULT_ACCOUNT}:policy/Nonexistent"
    )
    assert doc is None


# --------------------------------------------------------------------------- #
# create_update_customer_managed_policy
# --------------------------------------------------------------------------- #


@mock_aws
def test_create_update_creates_new_policy_with_cxmng_tag(
    deploy_module, aws_credentials, tmp_path
):
    """First-time execution creates the policy AND applies the cx-mng:true tag."""
    _create_deploy_role()
    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["NewPolicy"],
    )
    policies_folder = _write_policy(tmp_path / "policies", name="NewPolicy")
    args = _build_args(assignments_folder=assignments_folder, policies_folder=policies_folder)

    deploy_module.create_update_customer_managed_policy(args)

    iam = boto3.client("iam", region_name="us-east-1")
    policy_arn = f"arn:aws:iam::{DEFAULT_ACCOUNT}:policy/NewPolicy"
    iam.get_policy(PolicyArn=policy_arn)  # raises if missing

    tags = iam.list_policy_tags(PolicyArn=policy_arn)["Tags"]
    tag_dict = {t["Key"]: t["Value"] for t in tags}
    assert tag_dict.get("cx-mng") == "true"


@mock_aws
def test_create_update_applies_user_tags_alongside_cxmng_tag(
    deploy_module, aws_credentials, tmp_path
):
    """Tags from the policy JSON are applied along with the mandatory cx-mng tag."""
    _create_deploy_role()
    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["TaggedPolicy"],
    )
    policies_folder = _write_policy(
        tmp_path / "policies",
        name="TaggedPolicy",
        tags=[{"Key": "Owner", "Value": "team-x"}],
    )
    args = _build_args(assignments_folder=assignments_folder, policies_folder=policies_folder)

    deploy_module.create_update_customer_managed_policy(args)

    iam = boto3.client("iam", region_name="us-east-1")
    policy_arn = f"arn:aws:iam::{DEFAULT_ACCOUNT}:policy/TaggedPolicy"
    tags = iam.list_policy_tags(PolicyArn=policy_arn)["Tags"]
    tag_dict = {t["Key"]: t["Value"] for t in tags}
    assert tag_dict.get("cx-mng") == "true"
    assert tag_dict.get("Owner") == "team-x"


@mock_aws
def test_create_update_creates_new_version_for_existing_managed_policy(
    deploy_module, aws_credentials, tmp_path
):
    """Existing cx-mng policy with different content gets a new IAM version."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    # Pre-create the policy with an older document and the cx-mng tag.
    old_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}
    response = iam.create_policy(PolicyName="UpdMe", PolicyDocument=json.dumps(old_doc))
    policy_arn = response["Policy"]["Arn"]
    iam.tag_policy(PolicyArn=policy_arn, Tags=[{"Key": "cx-mng", "Value": "true"}])

    # New content via repo file.
    new_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["UpdMe"],
    )
    policies_folder = _write_policy(tmp_path / "policies", name="UpdMe", doc=new_doc)
    args = _build_args(assignments_folder=assignments_folder, policies_folder=policies_folder)

    deploy_module.create_update_customer_managed_policy(args)

    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions) == 2  # original + new
    default = next(v for v in versions if v["IsDefaultVersion"])
    fetched = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default["VersionId"])
    assert fetched["PolicyVersion"]["Document"] == new_doc


@mock_aws
def test_create_update_skips_when_hash_in_state_matches_repo(
    deploy_module, aws_credentials, tmp_path
):
    """If S3 state has the same hash as the repo, no new policy version is created."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    # Create policy with the doc + cx-mng tag.
    response = iam.create_policy(PolicyName="StablePolicy", PolicyDocument=json.dumps(DEFAULT_POLICY_DOC))
    policy_arn = response["Policy"]["Arn"]
    iam.tag_policy(PolicyArn=policy_arn, Tags=[{"Key": "cx-mng", "Value": "true"}])

    # Pre-populate S3 state with the same hash as the repo doc.
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="state-bucket")
    state = {
        "account_id": DEFAULT_ACCOUNT,
        "policies": {
            "StablePolicy": {
                "policy_hash": deploy_module.policy_hash(DEFAULT_POLICY_DOC),
                "version_id": "v1",
                "arn": policy_arn,
            }
        },
    }
    s3.put_object(
        Bucket="state-bucket",
        Key=f"state/{DEFAULT_ACCOUNT}.json",
        Body=json.dumps(state),
    )

    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["StablePolicy"],
    )
    policies_folder = _write_policy(tmp_path / "policies", name="StablePolicy")
    args = _build_args(
        assignments_folder=assignments_folder,
        policies_folder=policies_folder,
        state_bucket="state-bucket",
    )

    deploy_module.create_update_customer_managed_policy(args)

    # No new version should have been created.
    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions) == 1


@mock_aws
def test_create_update_skips_existing_policy_without_cxmng_tag(
    deploy_module, aws_credentials, tmp_path
):
    """Safety: don't touch policies that don't have the cx-mng:true tag."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    # Pre-create policy WITHOUT cx-mng tag.
    response = iam.create_policy(
        PolicyName="ExternalPolicy",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                    "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}),
    )
    policy_arn = response["Policy"]["Arn"]
    # No tag_policy call: safety-critical scenario.

    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["ExternalPolicy"],
    )
    policies_folder = _write_policy(tmp_path / "policies", name="ExternalPolicy")
    args = _build_args(assignments_folder=assignments_folder, policies_folder=policies_folder)

    deploy_module.create_update_customer_managed_policy(args)

    # Policy must remain untouched: still 1 version, still no tags.
    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions) == 1
    tags = iam.list_policy_tags(PolicyArn=policy_arn)["Tags"]
    tag_keys = {t["Key"] for t in tags}
    assert "cx-mng" not in tag_keys


@mock_aws
def test_create_update_dry_run_makes_no_api_mutations(
    deploy_module, aws_credentials, tmp_path
):
    """With --dry-run, no policy is created even when one is requested."""
    _create_deploy_role()
    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["DryRunPolicy"],
    )
    policies_folder = _write_policy(tmp_path / "policies", name="DryRunPolicy")
    args = _build_args(
        assignments_folder=assignments_folder,
        policies_folder=policies_folder,
        dry_run=True,
    )

    deploy_module.create_update_customer_managed_policy(args)

    iam = boto3.client("iam", region_name="us-east-1")
    policies = iam.list_policies(Scope="Local")["Policies"]
    names = [p["PolicyName"] for p in policies]
    assert "DryRunPolicy" not in names


# --------------------------------------------------------------------------- #
# delete_customer_managed_policy
# --------------------------------------------------------------------------- #


@mock_aws
def test_delete_removes_managed_policy_no_longer_in_assignments(
    deploy_module, aws_credentials, tmp_path
):
    """A cx-mng:true policy that's not in any current assignment is deleted."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    # Pre-create a managed policy that the assignments DO NOT mention.
    response = iam.create_policy(PolicyName="OrphanPolicy", PolicyDocument=json.dumps(DEFAULT_POLICY_DOC))
    orphan_arn = response["Policy"]["Arn"]
    iam.tag_policy(PolicyArn=orphan_arn, Tags=[{"Key": "cx-mng", "Value": "true"}])

    # Assignment references a different policy.
    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["OtherPolicy"],
    )
    policies_folder = _write_policy(tmp_path / "policies", name="OtherPolicy")
    args = _build_args(assignments_folder=assignments_folder, policies_folder=policies_folder)

    deploy_module.delete_customer_managed_policy(args)

    # Orphan must be gone.
    policies = iam.list_policies(Scope="Local")["Policies"]
    names = [p["PolicyName"] for p in policies]
    assert "OrphanPolicy" not in names


@mock_aws
def test_delete_preserves_policy_without_cxmng_tag(
    deploy_module, aws_credentials, tmp_path
):
    """Safety: never delete a policy that doesn't carry the cx-mng:true tag."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    # Pre-create a policy that's NOT managed by us (no cx-mng tag).
    response = iam.create_policy(
        PolicyName="HumanCreatedPolicy",
        PolicyDocument=json.dumps(DEFAULT_POLICY_DOC),
    )
    other_arn = response["Policy"]["Arn"]

    # Empty assignments — without the safety check, this policy would be deleted.
    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=[],
    )
    policies_folder = _write_policy(tmp_path / "policies", name="Unused")
    args = _build_args(assignments_folder=assignments_folder, policies_folder=policies_folder)

    deploy_module.delete_customer_managed_policy(args)

    # The human-owned policy must still be there.
    iam.get_policy(PolicyArn=other_arn)  # raises if it was deleted


@mock_aws
def test_delete_preserves_policy_currently_in_assignment(
    deploy_module, aws_credentials, tmp_path
):
    """A managed policy still referenced by an assignment is NOT deleted."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    response = iam.create_policy(PolicyName="KeepMe", PolicyDocument=json.dumps(DEFAULT_POLICY_DOC))
    keep_arn = response["Policy"]["Arn"]
    iam.tag_policy(PolicyArn=keep_arn, Tags=[{"Key": "cx-mng", "Value": "true"}])

    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["KeepMe"],
    )
    policies_folder = _write_policy(tmp_path / "policies", name="KeepMe")
    args = _build_args(assignments_folder=assignments_folder, policies_folder=policies_folder)

    deploy_module.delete_customer_managed_policy(args)

    iam.get_policy(PolicyArn=keep_arn)  # raises if it was deleted


@mock_aws
def test_delete_dry_run_makes_no_api_mutations(
    deploy_module, aws_credentials, tmp_path
):
    """With --dry-run, even an obvious deletion candidate is NOT removed."""
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    response = iam.create_policy(
        PolicyName="WouldDelete",
        PolicyDocument=json.dumps(DEFAULT_POLICY_DOC),
    )
    arn = response["Policy"]["Arn"]
    iam.tag_policy(PolicyArn=arn, Tags=[{"Key": "cx-mng", "Value": "true"}])

    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=[],  # empty → eligible for delete
    )
    policies_folder = _write_policy(tmp_path / "policies", name="Other")
    args = _build_args(
        assignments_folder=assignments_folder,
        policies_folder=policies_folder,
        dry_run=True,
    )

    deploy_module.delete_customer_managed_policy(args)

    iam.get_policy(PolicyArn=arn)  # still there


# --------------------------------------------------------------------------- #
# Resilience tests
#
# Cover what moto cannot simulate well:
#   * BOTO3_CONFIG actually being applied to clients (verified directly)
#   * IAM 5-policy-versions cap handling (delete oldest before create)
#   * EXTERNAL_ID env var being threaded into sts.assume_role calls
#
# Limitations these tests still do NOT catch (require real AWS):
#   * Whether boto3 actually retries on Throttling at runtime
#   * IAM permission evaluation
#   * Eventual consistency
# See tests/README.md for the full coverage analysis.
# --------------------------------------------------------------------------- #


def test_boto3_config_has_expected_timeouts_and_retries(deploy_module):
    """The shared BOTO3_CONFIG carries the timeouts and retry policy we declared."""
    config = deploy_module.BOTO3_CONFIG
    assert config.connect_timeout == 10
    assert config.read_timeout == 30
    assert config.retries.get("max_attempts") == 2
    assert config.retries.get("mode") == "adaptive"


@mock_aws
def test_get_iam_client_applies_boto3_config(deploy_module, aws_credentials):
    """The IAM client returned by get_iam_client carries our BOTO3_CONFIG."""
    _create_deploy_role()
    iam = deploy_module.get_iam_client(DEFAULT_ACCOUNT)
    assert iam.meta.config.connect_timeout == 10
    assert iam.meta.config.read_timeout == 30


# --- ExternalId behavior --- #


from unittest.mock import MagicMock, patch  # noqa: E402


def _make_sts_mock_returning_creds():
    """Build a MagicMock STS client that returns valid-looking assume_role creds."""
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIATEST",
            "SecretAccessKey": "secrettest",
            "SessionToken": "sessiontest",
        }
    }
    return sts


def _patch_boto3_clients(deploy_module, sts_mock, iam_mock):
    """Make deploy_module.boto3.client return sts_mock for sts and iam_mock for iam."""
    def fake_client(service_name, **_kwargs):
        if service_name == "sts":
            return sts_mock
        if service_name == "iam":
            return iam_mock
        raise AssertionError(f"Unexpected service in test: {service_name}")
    return patch.object(deploy_module.boto3, "client", side_effect=fake_client)


def test_get_iam_client_passes_external_id_when_env_var_set(
    deploy_module, monkeypatch
):
    """When EXTERNAL_ID env var is set, assume_role is called WITH ExternalId."""
    monkeypatch.setenv("EXTERNAL_ID", "test-external-id-1234567890")

    sts_mock = _make_sts_mock_returning_creds()
    iam_mock = MagicMock()

    with _patch_boto3_clients(deploy_module, sts_mock, iam_mock):
        deploy_module.get_iam_client("123456789012")

    sts_mock.assume_role.assert_called_once()
    call_kwargs = sts_mock.assume_role.call_args.kwargs
    assert call_kwargs.get("ExternalId") == "test-external-id-1234567890"
    assert call_kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/deploy-customer-managed-policy"


def test_get_iam_client_omits_external_id_when_env_var_unset(
    deploy_module, monkeypatch
):
    """When EXTERNAL_ID is absent, ExternalId is NOT passed (backward compat)."""
    monkeypatch.delenv("EXTERNAL_ID", raising=False)

    sts_mock = _make_sts_mock_returning_creds()
    iam_mock = MagicMock()

    with _patch_boto3_clients(deploy_module, sts_mock, iam_mock):
        deploy_module.get_iam_client("123456789012")

    sts_mock.assume_role.assert_called_once()
    call_kwargs = sts_mock.assume_role.call_args.kwargs
    assert "ExternalId" not in call_kwargs


def test_get_iam_client_omits_external_id_when_env_var_empty_string(
    deploy_module, monkeypatch
):
    """An empty EXTERNAL_ID is treated as unset — avoids passing '' to AWS."""
    monkeypatch.setenv("EXTERNAL_ID", "")

    sts_mock = _make_sts_mock_returning_creds()
    iam_mock = MagicMock()

    with _patch_boto3_clients(deploy_module, sts_mock, iam_mock):
        deploy_module.get_iam_client("123456789012")

    call_kwargs = sts_mock.assume_role.call_args.kwargs
    assert "ExternalId" not in call_kwargs


# --- end ExternalId behavior --- #


@mock_aws
def test_create_update_handles_five_version_cap(
    deploy_module, aws_credentials, tmp_path
):
    """When a policy already has 5 versions, the oldest non-default is deleted before creating a new one.

    Simulates the natural state after multiple pipeline runs:
      * v1: original default — demoted by v2's promotion, becomes oldest non-default
      * v2..v5: each created with SetAsDefault=True, latest is current default
    On the next update, the script must delete v1 (oldest) before create_policy_version
    or IAM rejects with LimitExceededException.
    """
    _create_deploy_role()
    iam = boto3.client("iam", region_name="us-east-1")

    # Create policy (v1, default) + cx-mng tag.
    base_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    response = iam.create_policy(PolicyName="MaxedOut", PolicyDocument=json.dumps(base_doc))
    policy_arn = response["Policy"]["Arn"]
    iam.tag_policy(PolicyArn=policy_arn, Tags=[{"Key": "cx-mng", "Value": "true"}])

    # Add 4 more versions, each as default — mirrors real pipeline behavior.
    for i in range(4):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": f"s3:Action{i}", "Resource": "*"}
            ],
        }
        iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(doc),
            SetAsDefault=True,
        )

    versions_before = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions_before) == 5  # at the IAM cap

    # Run create_update with a brand new doc that should trigger the cap-handling path.
    new_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:BrandNewAction", "Resource": "*"}
        ],
    }
    assignments_folder = _write_assignment(
        tmp_path / "assignments",
        sid="X", target=[DEFAULT_ACCOUNT], policies=["MaxedOut"],
    )
    policies_folder = _write_policy(
        tmp_path / "policies", name="MaxedOut", doc=new_doc,
    )
    args = _build_args(
        assignments_folder=assignments_folder, policies_folder=policies_folder,
    )

    deploy_module.create_update_customer_managed_policy(args)

    # Still 5 versions (1 deleted + 1 created); newest is the default.
    versions_after = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions_after) == 5
    default = next(v for v in versions_after if v["IsDefaultVersion"])
    fetched = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default["VersionId"])
    assert fetched["PolicyVersion"]["Document"] == new_doc
