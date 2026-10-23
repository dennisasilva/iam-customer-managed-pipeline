#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

"""Deploy IAM customer-managed policies to multiple AWS accounts.

This script is invoked by the pipeline's ``CustomerManagedPolicies`` stage (apply mode)
and ``DryRun`` stage (no mutation) and performs three high-level operations:

1. **Create / update**: For every ``(account, policy)`` pair declared in the assignment
   JSONs, ensure the IAM customer-managed policy exists with the desired document.
   A SHA-256 hash of the policy document is cached in S3 (``state/<account>.json``);
   if the hash hasn't changed the policy update is skipped, which avoids burning
   IAM policy versions unnecessarily.

2. **Drift detection**: While iterating, also compare the live policy document with
   the document the pipeline last deployed. A mismatch is logged as a warning.

3. **Delete**: Any ``Local`` policy carrying the ``cx-mng:true`` tag that is *not*
   referenced by any current assignment is deleted. Accounts that were managed in
   the past but are no longer listed in any ``Target`` are also visited so their
   stale policies are cleaned up.

Arguments:
    --dry-run:       Print what would happen but make no API calls that mutate IAM.
    --state-bucket:  S3 bucket where ``state/<account_id>.json`` files are kept.
                     If omitted, state is not used (every run will re-evaluate).
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone

import boto3
from botocore.config import Config


logging.basicConfig(
    format="%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.INFO,
)
LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Run-level failure tracking
# --------------------------------------------------------------------------- #
#
# The deploy must fail the CodePipeline stage (non-zero exit) when the live
# IAM resource diverged from the reviewed repository document (drift), was
# absent, could not be read, or could not be remediated. We also publish an
# alert so operators notice the broken-invariant case even if the stage is
# auto-retried. Per-policy exceptions are still caught and logged so one bad
# account does not stop the rest of the run — they are just now recorded here.
_run_failures: list = []


def _reset_run_failures() -> None:
    """Reset the module-level failure list (called at the start of main())."""
    _run_failures.clear()


def record_run_failure(account_id: str, policy_name: str, kind: str, detail: str = "") -> None:
    """Record a drift / absence / remediation failure for a single (account, policy).

    ``kind`` is one of ``drift``, ``absent``, ``read_failed``, ``remediation_failed``.
    The run will exit non-zero and emit an alert when any failures are recorded.
    """
    _run_failures.append(
        {
            "account_id": account_id,
            "policy_name": policy_name,
            "kind": kind,
            "detail": detail,
        }
    )


def _publish_failure_alert(failures: list) -> None:
    """Best-effort alert when drift/absence/remediation failures were recorded.

    Publishes to the SNS topic in ``ALERT_TOPIC_ARN`` when set. Alerting is a
    best-effort side-channel: a publish failure must not mask the main non-zero
    exit (which is what actually fails the pipeline stage).
    """
    topic_arn = os.environ.get("ALERT_TOPIC_ARN")
    if not topic_arn or not failures:
        return
    try:
        sns = boto3.client("sns", config=BOTO3_CONFIG)
        subject = "customer-managed-policies: drift or remediation failure"[:100]
        sns.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=json.dumps(
                {
                    "message": "customer-managed-policies deploy detected drift/absence/remediation failures",
                    "codebuild_build_id": os.environ.get("CODEBUILD_BUILD_ID", "local"),
                    "failure_count": len(failures),
                    "failures": failures,
                },
                indent=2,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - alerting must not override the main exit code
        LOG.error("Could not publish failure alert to %s: %s", topic_arn, exc)


# botocore client config used everywhere in this script:
#   * 10s connect / 30s read timeouts so a single unreachable account does not
#     stall the build until the CodeBuild TimeoutInMinutes (480) kicks in.
#   * 2 retry attempts with adaptive backoff to absorb transient throttling
#     without amplifying outages.
BOTO3_CONFIG = Config(
    connect_timeout=10,
    read_timeout=30,
    retries={"max_attempts": 2, "mode": "adaptive"},
)


# AWS account IDs are exactly 12 digits. Defense-in-depth: the upstream
# TemplateValidation stage already enforces this, but if this script is run
# locally or that stage is skipped, we re-validate before any STS call.
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")


# Default location of the JSON templates relative to this script's CWD. The
# pipeline's buildspec runs the script from ``source/customer-managed-policies/``,
# which is why the defaults walk two levels up. Both can be overridden on the
# command line for local testing or alternative repository layouts.
DEFAULT_ASSIGNMENTS_DIR = "../../templates/assignments"
DEFAULT_POLICIES_DIR = "../../templates/customer-managed-policies"

# Cross-account role assumed by the pipeline in every target account. Created by
# the ``cx-mng-stackset-deploy-role.yaml`` StackSet.
ROLE_NAME = "deploy-customer-managed-policy"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    """Parse and return the command-line arguments."""
    parser = argparse.ArgumentParser(description="Customer-managed policies deploy")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Print intended actions without calling any mutating IAM API.",
    )
    parser.add_argument(
        "--state-bucket",
        action="store",
        dest="state_bucket",
        default=None,
        help="S3 bucket holding state/<account>.json files. Optional.",
    )
    parser.add_argument(
        "--assignments-folder",
        action="store",
        dest="assignments_folder",
        default=DEFAULT_ASSIGNMENTS_DIR,
        help=f"Folder containing assignment JSON files. Default: {DEFAULT_ASSIGNMENTS_DIR}",
    )
    parser.add_argument(
        "--policies-folder",
        action="store",
        dest="policies_folder",
        default=DEFAULT_POLICIES_DIR,
        help=f"Folder containing policy JSON files. Default: {DEFAULT_POLICIES_DIR}",
    )
    return parser.parse_args()


def policy_hash(document: dict) -> str:
    """Return a stable SHA-256 of a policy document (sort_keys for determinism)."""
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()


def filter_tags(tags: list) -> list:
    """Drop tag entries that are missing Key or Value."""
    return [t for t in tags if t.get("Key") and t.get("Value")]


def _validate_account_id(account_id, context: str) -> None:
    """Raise ``ValueError`` if ``account_id`` is not a 12-digit string.

    ``context`` should describe where the value came from (e.g. assignment
    file + SID), so the error message points the operator at the offending
    JSON entry instead of just the value.
    """
    if not (isinstance(account_id, str) and ACCOUNT_ID_PATTERN.match(account_id)):
        raise ValueError(
            f"Invalid Target account ID {account_id!r} in {context}. "
            f"Must be exactly 12 digits "
            f"(did the TemplateValidation stage run before this?)."
        )


# Regex for chars *not* allowed in IAM RoleSessionName (allowed: [\w+=,.@-]).
# Used to sanitize CODEBUILD_BUILD_ID (which contains ':') before assembling
# a unique session name.
_SESSION_NAME_INVALID_CHARS = re.compile(r"[^\w+=,.@-]")


def _build_session_name(prefix: str = "CxMngDeploy") -> str:
    """Return a unique, IAM-compliant RoleSessionName traceable to this run.

    Uses ``CODEBUILD_BUILD_ID`` (e.g. ``project:abc12345-...``) when running
    inside CodeBuild, falling back to ``"local"`` otherwise. Colons and other
    chars not allowed in RoleSessionName are replaced with ``-``. The result is
    truncated to fit IAM's 64-char limit, keeping the *suffix* of the build ID
    (the unique UUID part) when the project name is long.
    """
    build_id = os.environ.get("CODEBUILD_BUILD_ID", "local")
    safe = _SESSION_NAME_INVALID_CHARS.sub("-", build_id)
    # Reserve room for the prefix + the separator '-'.
    max_suffix_len = max(1, 64 - len(prefix) - 1)
    # Truncate from the start; strip leading '-' that the cut may leave
    # behind, otherwise the result ends up with a cosmetic 'PREFIX--tail'.
    suffix = safe[-max_suffix_len:].lstrip("-") or "x"
    return f"{prefix}-{suffix}"


def load_state(s3_client, account_id: str, state_bucket: str) -> dict:
    """Load ``state/<account_id>.json`` from S3, or {} if missing/unreadable."""
    if not state_bucket:
        return {}
    try:
        obj = s3_client.get_object(Bucket=state_bucket, Key=f"state/{account_id}.json")
        return json.loads(obj["Body"].read())
    except s3_client.exceptions.NoSuchKey:
        return {}
    except Exception as exc:  # noqa: BLE001 - state read failures must not abort deploy
        LOG.warning("[%s] Could not read state: %s", account_id, exc)
        return {}


def save_state(s3_client, account_id: str, state: dict, state_bucket: str) -> None:
    """Persist ``state/<account_id>.json`` to S3, stamping ``last_execution`` in UTC."""
    if not state_bucket:
        return
    try:
        state["last_execution"] = datetime.now(timezone.utc).isoformat()
        s3_client.put_object(
            Bucket=state_bucket,
            Key=f"state/{account_id}.json",
            Body=json.dumps(state, indent=2),
            ContentType="application/json",
        )
        LOG.info(
            "[%s] State saved to s3://%s/state/%s.json",
            account_id, state_bucket, account_id,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.error("[%s] Could not save state: %s", account_id, exc)


def diff_policy(account_id: str, policy_name: str, old_doc: dict, new_doc: dict) -> None:
    """Log a per-statement / per-action / per-resource diff between two policy documents."""
    if old_doc == new_doc:
        return
    LOG.info("[%s] DIFF '%s':", account_id, policy_name)

    # Index statements by Sid so we can compare them across both versions.
    old_stmts = {s.get("Sid", f"stmt-{i}"): s for i, s in enumerate(old_doc.get("Statement", []))}
    new_stmts = {s.get("Sid", f"stmt-{i}"): s for i, s in enumerate(new_doc.get("Statement", []))}

    for sid in set(list(old_stmts.keys()) + list(new_stmts.keys())):
        if sid not in old_stmts:
            LOG.info("  + Statement '%s' ADDED", sid)
            continue
        if sid not in new_stmts:
            LOG.info("  - Statement '%s' REMOVED", sid)
            continue

        old_actions = set(old_stmts[sid].get("Action", []))
        new_actions = set(new_stmts[sid].get("Action", []))
        added = new_actions - old_actions
        removed = old_actions - new_actions
        if added:
            LOG.info("  Statement '%s' Actions added: %s", sid, added)
        if removed:
            LOG.info("  Statement '%s' Actions removed: %s", sid, removed)

        # Resource may be either a string or a list — normalize both sides to a set.
        old_res_field = old_stmts[sid].get("Resource", "")
        new_res_field = new_stmts[sid].get("Resource", "")
        old_res = set(old_res_field) if isinstance(old_res_field, list) else {old_res_field}
        new_res = set(new_res_field) if isinstance(new_res_field, list) else {new_res_field}
        res_added = new_res - old_res
        res_removed = old_res - new_res
        if res_added:
            LOG.info("  Statement '%s' Resources added: %s", sid, res_added)
        if res_removed:
            LOG.info("  Statement '%s' Resources removed: %s", sid, res_removed)


def get_current_policy_doc(iam_client, policy_arn: str):
    """Return the document of the default version of ``policy_arn``.

    Returns ``None`` when the policy does *not* exist (``NoSuchEntity`` from IAM).
    Any other exception — AccessDenied, throttling, transient boto errors, etc. —
    is re-raised so the caller can distinguish "policy absent" from "read failed",
    treat the latter as a drift/remediation failure, and fail the pipeline stage
    instead of silently assuming the live resource matches the repository.
    """
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy["Policy"]["DefaultVersionId"]
        version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return version["PolicyVersion"]["Document"]
    except iam_client.exceptions.NoSuchEntityException:
        return None


def get_iam_client(account_id: str):
    """Return an IAM client running with credentials from ``deploy-customer-managed-policy``.

    Reads the ``EXTERNAL_ID`` environment variable to fulfill the
    ``sts:ExternalId`` condition on the cross-account role's
    AssumeRolePolicyDocument. The variable is OPTIONAL — when absent (e.g. in
    moto-based tests or local dev with a role that has no condition), the
    ExternalId argument is omitted, and ``assume_role`` succeeds as long as
    the principal+action match.

    In production, the StackSet enforces ``sts:ExternalId``, so a missing
    EXTERNAL_ID env var will surface as ``AccessDenied`` from STS — caught
    upstream by the script's per-policy error handler.
    """
    sts = boto3.client("sts", config=BOTO3_CONFIG)
    assume_role_kwargs = {
        "RoleArn": f"arn:aws:iam::{account_id}:role/{ROLE_NAME}",
        "RoleSessionName": _build_session_name("CxMngDeploy"),
    }
    external_id = os.environ.get("EXTERNAL_ID")
    if external_id:
        assume_role_kwargs["ExternalId"] = external_id
    assumed = sts.assume_role(**assume_role_kwargs)
    creds = assumed["Credentials"]
    return boto3.client(
        "iam",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        config=BOTO3_CONFIG,
    )


# --------------------------------------------------------------------------- #
# Phase 1 — create / update
# --------------------------------------------------------------------------- #


def create_update_customer_managed_policy(args: argparse.Namespace) -> None:
    """Iterate every assignment and create or update each policy on each target account."""
    s3_client = boto3.client("s3", config=BOTO3_CONFIG) if args.state_bucket else None
    log_prefix = "[DRY-RUN] " if args.dry_run else ""

    for assignment_file in os.listdir(args.assignments_folder):
        if not assignment_file.endswith(".json"):
            continue
        with open(
            os.path.join(args.assignments_folder, assignment_file),
            "r",
            encoding="utf-8-sig",
        ) as f:
            assignments_data = json.load(f)

        for assignment in assignments_data.get("Assignments", []):
            policy_name_list = assignment.get("CustomerManagedPolicyName", [])
            target_accounts = assignment.get("Target", [])
            sid = assignment.get("SID", "?")

            for account_id in target_accounts:
                _validate_account_id(account_id, context=f"{assignment_file}#{sid}")
                LOG.info("%sProcessing account: %s", log_prefix, account_id)
                iam = get_iam_client(account_id)
                state = load_state(s3_client, account_id, args.state_bucket) if s3_client else {}
                policies_state = state.get("policies", {})

                for policy_file in os.listdir(args.policies_folder):
                    if not policy_file.endswith(".json"):
                        continue
                    with open(
                        os.path.join(args.policies_folder, policy_file),
                        "r",
                        encoding="utf-8-sig",
                    ) as pf:
                        policy_data = json.load(pf)

                    policy_name = policy_data.get("PolicyName")
                    # Skip policy templates that are not part of this assignment.
                    if policy_name not in policy_name_list:
                        continue

                    policy_document = policy_data["PolicyDocument"]
                    repo_hash = policy_hash(policy_document)
                    policy_tags = filter_tags(policy_data.get("Tags", []))
                    path = policy_data.get("Path", "/")
                    description = policy_data.get("Description", "Custom managed policy")

                    # Fast path: state hash matches repo hash. But cached state is
                    # not authoritative — a privileged principal in the member
                    # account can mutate or delete the live policy out-of-band, so
                    # we must compare against the live document, not the cache.
                    # If the live document matches the repo document we can safely
                    # skip the create_policy_version call (which avoids burning IAM
                    # policy versions). Any divergence — drift, policy deleted, or
                    # unreadable — falls through to the normal update/create branch
                    # below so the reviewed document is re-applied.
                    saved = policies_state.get(policy_name, {})
                    policy_arn = f"arn:aws:iam::{account_id}:policy{path}{policy_name}"
                    if saved.get("policy_hash") == repo_hash:
                        try:
                            current_doc = get_current_policy_doc(iam, policy_arn)
                        except Exception as exc:  # noqa: BLE001
                            # Unexplained read failure (e.g. AccessDenied, throttling).
                            # We cannot assert the live resource matches the repo,
                            # so flag this run as failed and move on. Do NOT attempt
                            # a blind update — we have no evidence of the live state.
                            LOG.error(
                                "%s[%s] Could not read live policy '%s' to verify state: %s",
                                log_prefix, account_id, policy_name, exc,
                            )
                            record_run_failure(
                                account_id, policy_name, "read_failed", str(exc)
                            )
                            continue
                        if current_doc is None:
                            # Policy was deleted in the member account despite cached
                            # state claiming it is deployed. Flag the run as failed
                            # and fall through to the create branch to recreate it.
                            LOG.warning(
                                "%s[%s] ABSENCE detected on '%s' (cached state is stale)! Recreating.",
                                log_prefix, account_id, policy_name,
                            )
                            record_run_failure(account_id, policy_name, "absent")
                            # Fall through to the create/update branch below.
                        elif policy_hash(current_doc) != repo_hash:
                            # Live document was mutated out-of-band. Flag the run as
                            # failed and fall through to re-apply the reviewed doc.
                            LOG.warning(
                                "%s[%s] DRIFT detected on '%s'! Re-applying reviewed document.",
                                log_prefix, account_id, policy_name,
                            )
                            record_run_failure(account_id, policy_name, "drift")
                            # Fall through to the create/update branch below.
                        else:
                            LOG.info(
                                "%s[%s] '%s' unchanged (hash match, live doc verified). Skipping.",
                                log_prefix, account_id, policy_name,
                            )
                            continue

                    try:
                        iam.get_policy(PolicyArn=policy_arn)
                        tags_response = iam.list_policy_tags(PolicyArn=policy_arn)
                        existing_tags = {t["Key"]: t["Value"] for t in tags_response["Tags"]}

                        # Safety check: only touch policies tagged as managed by this pipeline.
                        if existing_tags.get("cx-mng") != "true":
                            LOG.info(
                                "%s[%s] '%s' has no cx-mng:true tag. Skipping.",
                                log_prefix, account_id, policy_name,
                            )
                            continue

                        current_doc = get_current_policy_doc(iam, policy_arn)
                        if current_doc:
                            diff_policy(account_id, policy_name, current_doc, policy_document)

                        LOG.info("%s[%s] UPDATE '%s'", log_prefix, account_id, policy_name)
                        if not args.dry_run:
                            # IAM allows up to 5 versions of a managed policy; if we are
                            # already at the cap, drop the oldest non-default version first.
                            versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
                            if len(versions) >= 5:
                                oldest = sorted(versions, key=lambda v: v["CreateDate"])[0]
                                iam.delete_policy_version(
                                    PolicyArn=policy_arn, VersionId=oldest["VersionId"]
                                )

                            response = iam.create_policy_version(
                                PolicyArn=policy_arn,
                                PolicyDocument=json.dumps(policy_document),
                                SetAsDefault=True,
                            )
                            if policy_tags:
                                iam.tag_policy(PolicyArn=policy_arn, Tags=policy_tags)

                            policies_state[policy_name] = {
                                "arn": policy_arn,
                                "version_id": response["PolicyVersion"]["VersionId"],
                                "policy_hash": repo_hash,
                                "last_deployed": datetime.now(timezone.utc).isoformat(),
                            }
                            LOG.info("[%s] '%s' updated.", account_id, policy_name)

                    except iam.exceptions.NoSuchEntityException:
                        # Policy does not exist yet → create it.
                        LOG.info("%s[%s] CREATE '%s'", log_prefix, account_id, policy_name)
                        if not args.dry_run:
                            response = iam.create_policy(
                                PolicyName=policy_name,
                                Path=path,
                                PolicyDocument=json.dumps(policy_document),
                                Description=description,
                            )
                            policy_arn = response["Policy"]["Arn"]
                            tags_to_apply = [{"Key": "cx-mng", "Value": "true"}] + policy_tags
                            iam.tag_policy(PolicyArn=policy_arn, Tags=tags_to_apply)

                            policies_state[policy_name] = {
                                "arn": policy_arn,
                                "version_id": "v1",
                                "policy_hash": repo_hash,
                                "last_deployed": datetime.now(timezone.utc).isoformat(),
                            }
                            LOG.info("[%s] '%s' created.", account_id, policy_name)

                    except Exception as exc:  # noqa: BLE001 - per-policy failures must not stop the run
                        LOG.error("[%s] Error on '%s': %s", account_id, policy_name, exc)
                        record_run_failure(
                            account_id, policy_name, "remediation_failed", str(exc)
                        )

                if not args.dry_run and s3_client:
                    state["account_id"] = account_id
                    state["policies"] = policies_state
                    save_state(s3_client, account_id, state, args.state_bucket)


# --------------------------------------------------------------------------- #
# Phase 2 — delete
# --------------------------------------------------------------------------- #


def get_previously_managed_accounts(s3_client, state_bucket: str) -> set:
    """Return the set of account IDs that have a state file under ``state/`` in the bucket."""
    if not s3_client or not state_bucket:
        return set()
    try:
        response = s3_client.list_objects_v2(Bucket=state_bucket, Prefix="state/")
        accounts: set = set()
        for obj in response.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json"):
                continue
            account_id = key.replace("state/", "").replace(".json", "")
            if account_id.isdigit():
                accounts.add(account_id)
        return accounts
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Could not list state objects in S3: %s", exc)
        return set()


def delete_customer_managed_policy(args: argparse.Namespace) -> None:
    """Remove pipeline-managed policies that are no longer referenced by any assignment."""
    s3_client = boto3.client("s3", config=BOTO3_CONFIG) if args.state_bucket else None
    log_prefix = "[DRY-RUN] " if args.dry_run else ""

    # Build {account_id: {policy_name, ...}} of policies that should remain in each account.
    policies_per_account: dict = {}
    all_target_accounts: set = set()

    for assignment_file in os.listdir(args.assignments_folder):
        if not assignment_file.endswith(".json"):
            continue
        with open(
            os.path.join(args.assignments_folder, assignment_file),
            "r",
            encoding="utf-8-sig",
        ) as f:
            assignments_data = json.load(f)
        for assignment in assignments_data.get("Assignments", []):
            policies = assignment.get("CustomerManagedPolicyName", [])
            sid = assignment.get("SID", "?")
            for account_id in assignment.get("Target", []):
                _validate_account_id(account_id, context=f"{assignment_file}#{sid}")
                all_target_accounts.add(account_id)
                policies_per_account.setdefault(account_id, set()).update(policies)

    # Pick up accounts we managed in the past but are no longer listed anywhere.
    previous_accounts = get_previously_managed_accounts(s3_client, args.state_bucket)
    removed_accounts = previous_accounts - all_target_accounts
    if removed_accounts:
        LOG.info("Accounts removed from assignments (detected via state): %s", removed_accounts)
    all_accounts_to_check = all_target_accounts | removed_accounts

    for account_id in all_accounts_to_check:
        # For accounts that were removed, no policy should remain.
        keep_for_account = policies_per_account.get(account_id, set())
        iam = get_iam_client(account_id)
        state = load_state(s3_client, account_id, args.state_bucket) if s3_client else {}
        policies_state = state.get("policies", {})

        response = iam.list_policies(Scope="Local")
        for policy in response["Policies"]:
            policy_name = policy["PolicyName"]
            policy_arn = policy["Arn"]

            if policy_name in keep_for_account:
                continue
            try:
                tags_response = iam.list_policy_tags(PolicyArn=policy_arn)
                tags = {t["Key"]: t["Value"] for t in tags_response["Tags"]}
                # Only delete policies that this pipeline created.
                if tags.get("cx-mng") != "true":
                    continue

                LOG.info("%s[%s] DELETE '%s'", log_prefix, account_id, policy_name)
                if not args.dry_run:
                    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
                    for version in versions:
                        if not version["IsDefaultVersion"]:
                            iam.delete_policy_version(
                                PolicyArn=policy_arn, VersionId=version["VersionId"]
                            )
                    iam.delete_policy(PolicyArn=policy_arn)
                    policies_state.pop(policy_name, None)
                    LOG.info("[%s] '%s' deleted.", account_id, policy_name)
            except Exception as exc:  # noqa: BLE001
                LOG.error("[%s] Error deleting '%s': %s", account_id, policy_name, exc)
                record_run_failure(
                    account_id, policy_name, "remediation_failed", f"delete: {exc}"
                )

        if not args.dry_run and s3_client:
            state["account_id"] = account_id
            state["policies"] = policies_state
            if policies_state:
                save_state(s3_client, account_id, state, args.state_bucket)
            elif account_id in removed_accounts:
                # Account is gone from assignments and has no policies left — drop its state file.
                try:
                    s3_client.delete_object(
                        Bucket=args.state_bucket, Key=f"state/{account_id}.json"
                    )
                    LOG.info("[%s] State removed from S3.", account_id)
                except Exception as exc:  # noqa: BLE001
                    LOG.warning("[%s] Could not remove state: %s", account_id, exc)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def main() -> int:
    """Run create/update then delete.

    Returns a non-zero exit code when any drift, out-of-band deletion, read
    failure, or per-policy remediation error was recorded, so the CodePipeline
    stage fails loudly instead of logging a warning that nobody reads. A
    best-effort SNS alert is published when ``ALERT_TOPIC_ARN`` is set.
    """
    _reset_run_failures()
    args = parse_args()
    create_update_customer_managed_policy(args)
    delete_customer_managed_policy(args)
    if _run_failures:
        LOG.error(
            "customer-managed-policies deploy finished with %d failure(s): %s",
            len(_run_failures),
            _run_failures,
        )
        _publish_failure_alert(list(_run_failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
