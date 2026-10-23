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

# See customer-managed-validation.py for the rationale and format of this
# environment variable. We re-read it here so that even if TemplateValidation
# is skipped or bypassed (local run, split pipeline, future refactor), the
# cross-account STS calls below cannot be pointed at an unapproved account.
ALLOWED_TARGET_ACCOUNT_IDS_ENV = "ALLOWED_TARGET_ACCOUNT_IDS"


def _get_allowed_target_accounts():
    """Return (set | None) of pinned account IDs from the environment.

    ``None`` -> variable unset (local/dev invocations). Caller should warn.
    ``set``  -> enforce membership before issuing any sts:AssumeRole.
    """
    raw = os.environ.get(ALLOWED_TARGET_ACCOUNT_IDS_ENV)
    if raw is None:
        return None
    allowed = set()
    for token in re.split(r"[\s,;]+", raw.strip()):
        if token and ACCOUNT_ID_PATTERN.match(token):
            allowed.add(token)
    return allowed

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

    Exits the process with status 1 if the folder does not exist or if any
    Target entry is not a 12-digit account ID.
    """
    if not os.path.isdir(folder):
        LOG.error("Assignments folder '%s' not found.", folder)
        sys.exit(1)

    accounts: set = set()
    invalid: list = []

    for filename in os.listdir(folder):
        if not filename.endswith(".json"):
            continue
        with open(os.path.join(folder, filename), "r", encoding="utf-8-sig") as file_handle:
            data = json.load(file_handle)
        for assignment in data.get("Assignments", []):
            for account_id in assignment.get("Target", []):
                if isinstance(account_id, str) and ACCOUNT_ID_PATTERN.match(account_id):
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

    # Enforce the pinned allowlist as a second, independent check so a bypass
    # of TemplateValidation cannot cause an sts:AssumeRole against an
    # unapproved account (and thus leak the shared ExternalId to a foreign
    # CloudTrail). When the variable is unset we warn and continue, which
    # keeps local invocations and unit tests working.
    allowed = _get_allowed_target_accounts()
    if allowed is None:
        LOG.warning(
            "%s is not set; proceeding without an account allowlist. "
            "The pipeline buildspec MUST set this variable in production.",
            ALLOWED_TARGET_ACCOUNT_IDS_ENV,
        )
    elif not allowed:
        LOG.error(
            "%s is set but contains no valid 12-digit account IDs; refusing to proceed.",
            ALLOWED_TARGET_ACCOUNT_IDS_ENV,
        )
        sys.exit(1)
    else:
        unauthorized = sorted(accounts - allowed)
        if unauthorized:
            LOG.error(
                "Target account(s) %s are not in the authoritative allowlist (%s). "
                "Refusing to assume cross-account roles into unapproved accounts.",
                unauthorized, ALLOWED_TARGET_ACCOUNT_IDS_ENV,
            )
            sys.exit(1)

    LOG.info("Target accounts discovered: %s", accounts)
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
        LOG.error("[%s] Role '%s' is not accessible: %s", account_id, ROLE_NAME, exc)
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
            "Role '%s' is missing or not accessible on accounts: %s", ROLE_NAME, failures
        )
        LOG.error("Make sure the StackSet has created the role on these accounts.")
        return 1

    LOG.info("Role validation completed successfully on all target accounts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
