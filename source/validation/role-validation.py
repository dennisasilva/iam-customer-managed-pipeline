#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

"""Pre-deploy validation for the cross-account ``deploy-customer-managed-policy`` role.

Runs as part of the pipeline ``RoleValidation`` stage. For every account listed
in any ``Target`` array of the assignment JSONs, the script tries to assume the
``deploy-customer-managed-policy`` role and call ``iam:GetRole`` from there.

If even one account fails the check, the script exits non-zero so the pipeline
stops *before* the deploy stage runs and partially mutates state.

Arguments:
    --assignments-folder: Folder containing assignment JSON files. Required.
"""

import argparse
import json
import logging
import os
import re
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


logging.basicConfig(
    format="%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.INFO,
)
LOG = logging.getLogger(__name__)

# Name of the IAM role expected to exist in each target account. Created by
# the ``cx-mng-stackset-deploy-role.yaml`` StackSet.
ROLE_NAME = "deploy-customer-managed-policy"

# AWS account IDs are exactly 12 digits. Defense-in-depth: this script may run
# without the upstream TemplateValidation stage (e.g. local debugging), so we
# re-validate before any STS call.
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")

# Pipeline-wide allow-list of accounts this build is permitted to manage,
# injected as a comma-separated ``ALLOWED_ACCOUNT_IDS`` environment variable
# by every CodeBuild project in cfn/cx-mng-pipeline.yaml / terraform/codebuild.tf.
# When set, any Target entry in the assignment JSON that is not in this list
# fails the stage *before* any STS call is attempted, preventing a repository
# writer from making the pipeline probe arbitrary foreign accounts. The env
# var is optional (empty / missing) only for local development and tests; in
# that case the containment is still enforced by the IAM-side
# aws:ResourceAccount / aws:ResourceOrgID condition on the pipeline role.


def _load_allowed_account_ids() -> "set[str] | None":
    """Return the parsed allow-list, or ``None`` when the env var is unset/empty.

    Each entry must match :data:`ACCOUNT_ID_PATTERN`; invalid entries cause
    the process to exit non-zero so a misconfigured pipeline fails loudly
    instead of silently falling back to "allow any 12-digit account".
    """
    raw = os.environ.get("ALLOWED_ACCOUNT_IDS", "").strip()
    if not raw:
        return None
    parsed = {token.strip() for token in raw.split(",") if token.strip()}
    invalid = sorted(a for a in parsed if not ACCOUNT_ID_PATTERN.match(a))
    if invalid:
        LOG.error(
            "ALLOWED_ACCOUNT_IDS contains invalid 12-digit entries: %s", invalid
        )
        sys.exit(1)
    return parsed

# Regex for chars *not* allowed in IAM RoleSessionName (allowed: [\w+=,.@-]).
_SESSION_NAME_INVALID_CHARS = re.compile(r"[^\w+=,.@-]")


def _build_session_name(prefix: str = "CxMngValidate") -> str:
    """Return a unique, IAM-compliant RoleSessionName traceable to this run.

    Uses ``CODEBUILD_BUILD_ID`` when running inside CodeBuild (so each build
    gets a unique session name visible in CloudTrail), falling back to
    ``"local"`` otherwise. Colons and other chars not allowed in
    RoleSessionName are replaced with ``-``. Truncated to IAM's 64-char limit.
    """
    build_id = os.environ.get("CODEBUILD_BUILD_ID", "local")
    safe = _SESSION_NAME_INVALID_CHARS.sub("-", build_id)
    max_suffix_len = max(1, 64 - len(prefix) - 1)
    suffix = safe[-max_suffix_len:].lstrip("-") or "x"
    return f"{prefix}-{suffix}"

# botocore client config:
#   * 10s connect / 30s read timeouts so a single unreachable account does not
#     stall the build until the CodeBuild TimeoutInMinutes (480) kicks in.
#   * 2 retry attempts with adaptive backoff to absorb transient throttling.
BOTO3_CONFIG = Config(
    connect_timeout=10,
    read_timeout=30,
    retries={"max_attempts": 2, "mode": "adaptive"},
)


def parse_args() -> argparse.Namespace:
    """Parse and return the command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate the cross-account deploy role on every target account."
    )
    parser.add_argument(
        "--assignments-folder",
        dest="assignments_folder",
        required=True,
        help="Folder containing assignment JSON files.",
    )
    return parser.parse_args()


def get_target_accounts(folder: str) -> set:
    """Read every ``*.json`` file in ``folder`` and return the union of all ``Target`` arrays.

    Exits the process with status 1 if the folder does not exist, if any
    Target entry is not a 12-digit account ID, or if any Target entry is
    outside the ``ALLOWED_ACCOUNT_IDS`` allow-list (when set). The allow-list
    check is the application-layer complement of the IAM
    ``aws:ResourceAccount`` / ``aws:ResourceOrgID`` condition on the pipeline
    role: it stops the stage *before* any ``sts:AssumeRole`` is attempted,
    so a repository writer cannot use the build log as a reconnaissance
    oracle against accounts outside the pipeline's management scope.
    """
    if not os.path.isdir(folder):
        LOG.error("Assignments folder '%s' not found.", folder)
        sys.exit(1)

    allowed = _load_allowed_account_ids()
    accounts: set = set()
    invalid: list = []
    out_of_scope: list = []

    for filename in os.listdir(folder):
        if not filename.endswith(".json"):
            continue
        with open(os.path.join(folder, filename), "r", encoding="utf-8-sig") as file_handle:
            data = json.load(file_handle)
        for assignment in data.get("Assignments", []):
            for account_id in assignment.get("Target", []):
                if isinstance(account_id, str) and ACCOUNT_ID_PATTERN.match(account_id):
                    if allowed is not None and account_id not in allowed:
                        out_of_scope.append(f"{filename}: {account_id}")
                        continue
                    accounts.add(account_id)
                else:
                    invalid.append(f"{filename}: {account_id!r}")

    if invalid:
        LOG.error("Invalid Target account ID(s) found: %s", invalid)
        LOG.error(
            "Run customer-managed-validation.py "
            "(TemplateValidation stage) to detect these earlier."
        )
        sys.exit(1)

    if out_of_scope:
        LOG.error(
            "Target account ID(s) outside the ALLOWED_ACCOUNT_IDS allow-list: %s",
            out_of_scope,
        )
        LOG.error(
            "Add these accounts to the AllowedAccountIds stack parameter "
            "(or terraform variable allowed_account_ids) if they really "
            "belong to the pipeline's management scope."
        )
        sys.exit(1)

    LOG.info("Target accounts discovered: %d account(s)", len(accounts))
    return accounts


def check_role_exists(account_id: str) -> bool:
    """Return True if ``ROLE_NAME`` is assumable from this caller in ``account_id``.

    Reads the ``EXTERNAL_ID`` environment variable to satisfy the
    ``sts:ExternalId`` condition on the cross-account role's
    AssumeRolePolicyDocument. When absent, the argument is omitted (allows
    moto-based tests and local dev against roles without the condition).
    """
    sts = boto3.client("sts", config=BOTO3_CONFIG)
    try:
        assume_role_kwargs = {
            "RoleArn": f"arn:aws:iam::{account_id}:role/{ROLE_NAME}",
            "RoleSessionName": _build_session_name("CxMngValidate"),
        }
        external_id = os.environ.get("EXTERNAL_ID")
        if external_id:
            assume_role_kwargs["ExternalId"] = external_id
        assumed = sts.assume_role(**assume_role_kwargs)
        creds = assumed["Credentials"]
        iam = boto3.client(
            "iam",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            config=BOTO3_CONFIG,
        )
        iam.get_role(RoleName=ROLE_NAME)
        LOG.info("[%s] Role '%s' validated successfully.", account_id, ROLE_NAME)
        return True
    except (ClientError, BotoCoreError) as exc:
        # Deliberately NOT logging the raw STS/IAM error text per account:
        # the verbatim message distinguishes "role does not exist" from
        # "role exists but denies us", which would turn this stage into a
        # cross-account existence oracle for any repository writer. Error
        # class is enough for an operator to triage without disclosing
        # which specific accounts have the role present.
        LOG.error(
            "[%s] Role '%s' is not accessible (%s).",
            account_id,
            ROLE_NAME,
            type(exc).__name__,
        )
        return False


def main() -> int:
    """Validate the deploy role across every target account. Returns 0 on success."""
    args = parse_args()

    accounts = get_target_accounts(args.assignments_folder)
    if not accounts:
        LOG.error("No target accounts found in any assignment file.")
        return 1

    failures = [acct for acct in accounts if not check_role_exists(acct)]
    if failures:
        LOG.error(
            "Role '%s' is missing or not accessible on %d account(s).",
            ROLE_NAME,
            len(failures),
        )
        LOG.error("Make sure the StackSet has created the role on these accounts.")
        return 1

    LOG.info("Role validation completed successfully on all target accounts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
