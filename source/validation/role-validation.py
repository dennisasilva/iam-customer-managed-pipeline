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

# Shape of the cross-account ExternalId shared secret. Must match the
# constraint applied by the pipeline's CloudFormation / Terraform input and
# by the ``deploy-customer-managed-policy`` trust policy generator.
EXTERNAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

# Regex for chars *not* allowed in IAM RoleSessionName (allowed: [\w+=,.@-]).
_SESSION_NAME_INVALID_CHARS = re.compile(r"[^\w+=,.@-]")


def load_external_id() -> str:
    """Return the ExternalId shared secret or abort the process.

    The value is read exactly once, at start-up, from the ``EXTERNAL_ID``
    environment variable (which, in production, is sourced from AWS Secrets
    Manager / SSM SecureString via the CodeBuild ``EnvironmentVariables``
    block of type ``SECRETS_MANAGER`` or ``PARAMETER_STORE``).

    Fails closed with ``SystemExit(1)`` when the value is missing, empty, or
    does not match the documented ``^[A-Za-z0-9_-]{16,64}$`` shape, so the
    pipeline refuses to issue a single ``sts:assume_role`` call without the
    second factor that protects the cross-account trust.
    """
    external_id = os.environ.get("EXTERNAL_ID")
    if external_id is None or external_id == "":
        LOG.error(
            "EXTERNAL_ID environment variable is required but is unset or empty. "
            "Refusing to call sts:AssumeRole without the cross-account ExternalId "
            "shared secret. Source it from Secrets Manager / SSM SecureString via "
            "the CodeBuild EnvironmentVariables block."
        )
        sys.exit(1)
    if not EXTERNAL_ID_PATTERN.match(external_id):
        LOG.error(
            "EXTERNAL_ID does not match the required shape "
            "'^[A-Za-z0-9_-]{16,64}$'. Refusing to call sts:AssumeRole with a "
            "malformed ExternalId."
        )
        sys.exit(1)
    return external_id


def _trust_policy_enforces_external_id(trust_doc: dict, expected_external_id: str) -> bool:
    """Return True iff ``trust_doc`` carries a ``sts:ExternalId`` condition
    that pins the expected shared-secret value on every statement that allows
    ``sts:AssumeRole`` for this caller.

    Checks ``StringEquals`` (case-sensitive) on ``sts:ExternalId`` /
    ``sts:externalid`` (IAM condition keys are case-insensitive). A statement
    is accepted only if its condition pins the ExternalId to the value the
    caller just used; a missing or mismatched condition fails closed.
    """
    if not isinstance(trust_doc, dict):
        return False
    statements = trust_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not statements:
        return False
    for stmt in statements:
        if not isinstance(stmt, dict):
            return False
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not any(
            isinstance(a, str) and a.lower() in ("sts:assumerole", "sts:*", "*")
            for a in actions
        ):
            continue
        condition = stmt.get("Condition")
        if not isinstance(condition, dict):
            return False
        string_equals = condition.get("StringEquals") or condition.get("stringEquals")
        if not isinstance(string_equals, dict):
            return False
        # IAM condition keys are case-insensitive.
        pinned = None
        for key, value in string_equals.items():
            if isinstance(key, str) and key.lower() == "sts:externalid":
                pinned = value
                break
        if pinned is None:
            return False
        if isinstance(pinned, list):
            if expected_external_id not in pinned:
                return False
        elif pinned != expected_external_id:
            return False
    return True


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

    LOG.info("Target accounts discovered: %s", accounts)
    return accounts


def check_role_exists(account_id: str, external_id: str = None) -> bool:
    """Return True if ``ROLE_NAME`` is assumable from this caller in ``account_id``
    AND the trust policy of that role actually pins the ``sts:ExternalId``
    condition to the shared secret this run is using.

    ``external_id`` is the shared secret used for ``sts:AssumeRole``. It is
    always passed to STS. When not provided, it is loaded (and validated)
    from the ``EXTERNAL_ID`` environment variable; the process exits
    non-zero if the variable is missing, empty, or malformed.

    Validation steps:

    1. ``sts:AssumeRole`` with ``ExternalId`` set. If the target trust policy
       does not pin the condition, STS fails closed with ``AccessDenied``.
    2. ``iam:GetRole`` on the assumed role to retrieve the trust policy and
       assert, client-side, that the ``sts:ExternalId`` condition is present
       and pins the expected value. A role provisioned without the
       condition (e.g. by hand, or by an older template) therefore fails
       this stage even if the target account happens to allow the assume.
    """
    if external_id is None:
        external_id = load_external_id()
    sts = boto3.client("sts", config=BOTO3_CONFIG)
    try:
        assume_role_kwargs = {
            "RoleArn": f"arn:aws:iam::{account_id}:role/{ROLE_NAME}",
            "RoleSessionName": _build_session_name("CxMngValidate"),
            "ExternalId": external_id,
        }
        assumed = sts.assume_role(**assume_role_kwargs)
        creds = assumed["Credentials"]
        iam = boto3.client(
            "iam",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            config=BOTO3_CONFIG,
        )
        role = iam.get_role(RoleName=ROLE_NAME)
        trust_doc = role.get("Role", {}).get("AssumeRolePolicyDocument")
        if not _trust_policy_enforces_external_id(trust_doc, external_id):
            LOG.error(
                "[%s] Role '%s' trust policy does NOT enforce the sts:ExternalId "
                "condition for the expected shared secret. Failing closed.",
                account_id,
                ROLE_NAME,
            )
            return False
        LOG.info("[%s] Role '%s' validated successfully.", account_id, ROLE_NAME)
        return True
    except (ClientError, BotoCoreError) as exc:
        LOG.error("[%s] Role '%s' is not accessible: %s", account_id, ROLE_NAME, exc)
        return False


def main() -> int:
    """Validate the deploy role across every target account. Returns 0 on success."""
    args = parse_args()

    # Fail fast, before any sts:AssumeRole call, if the required
    # cross-account shared secret is unset, empty, or malformed.
    external_id = load_external_id()

    accounts = get_target_accounts(args.assignments_folder)
    if not accounts:
        LOG.error("No target accounts found in any assignment file.")
        return 1

    failures = [acct for acct in accounts if not check_role_exists(acct, external_id)]
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
