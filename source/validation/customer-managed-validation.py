#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""IAM customer-managed policy template validation.

Runs as part of the pipeline TemplateValidation stage. Performs:

* JSON syntax validation of every *.json file in the policies folder.
* Uniqueness check on the PolicyName field across all policy templates.
* Path and target account-ID shape checks.
* Structural validation of the PolicyDocument body: rejects admin-equivalent
  patterns (Action: "*", service-wide wildcards on sensitive services such
  as iam:* / sts:*, NotAction / NotResource, Effect: Allow with
  Resource: "*" on sensitive services) and enforces IAM's 6144-char
  managed-policy size limit.
* IAM Access Analyzer ValidatePolicy (PolicyType=IDENTITY_POLICY) on every
  PolicyDocument. Build fails on ERROR or SECURITY_WARNING findings.

Arguments:
    --policies-folder:        Folder containing customer-managed policy JSON files.
    --assignments-folder:     Folder containing assignment JSON files (reserved for
                              future cross-checks; accepted but not used yet).
    --access-analyzer-region: AWS region for the Access Analyzer client
                              (defaults to AWS_REGION / us-east-1).
    --skip-access-analyzer:   Skip the Access Analyzer call. INTENDED FOR LOCAL
                              DEVELOPMENT ONLY. Must not be set in the pipeline.
"""

import argparse
import json
import logging
import os
import re
import sys


# Module-level logger configured in main() so importing the module has no side effects.
LOG = logging.getLogger(__name__)


# IAM Path validation rules:
#   * Must start and end with '/'.
#   * 1-512 characters total.
#   * Each segment between slashes contains only safe chars: A-Z a-z 0-9 . _ = + -
#   * No empty segments (no '//' anywhere in the path).
# IAM itself is more permissive (allows any printable ASCII), but a stricter
# pattern catches typos and prevents surprising ARN composition.
POLICY_PATH_PATTERN = re.compile(r"^/(?:[A-Za-z0-9._=+-]+/)*$")
POLICY_PATH_MAX_LENGTH = 512

# AWS account IDs are exactly 12 digits. Anything else here (typos, trailing
# whitespace, formatted numbers from spreadsheets, missing leading zeros) leads
# to confusing AccessDenied errors at runtime when the role lookup fails.
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")

# IAM managed-policy document size limit (minified) in characters.
# See IAM quotas documentation on the AWS website.
POLICY_DOCUMENT_MAX_LENGTH = 6144

# IAM policy language versions we accept. 2008-10-17 does not support policy
# variables and is a legacy format; new policies must use 2012-10-17.
ALLOWED_POLICY_VERSIONS = {"2012-10-17"}

# Shape of a single IAM Action value: either '*', 'service:*', or
# 'service:Verb'. The service prefix is lowercase ASCII; the verb accepts
# any non-empty mix of letters, digits, '*' and '?' (IAM supports in-string
# wildcards such as 'ec2:*SecurityGroup*').
ACTION_PATTERN = re.compile(r"^(?:\*|[a-z0-9-]+:[A-Za-z0-9*?]+)$")

# Services whose service-wide wildcards (svc:*) or Resource: "*" with
# Effect: Allow are refused outright by local structural validation.
# These are services that grant privilege-escalation primitives directly:
# identity, key management, org structure, audit controls, secret material.
SENSITIVE_SERVICES = frozenset({
    "iam",
    "sts",
    "kms",
    "organizations",
    "cloudtrail",
    "config",
    "access-analyzer",
    "accessanalyzer",
    "secretsmanager",
    "sso",
    "sso-admin",
    "identitystore",
    "ssm",
})

# IAM actions that are, on their own, equivalent to administrative access or
# a direct privilege-escalation primitive. Rejected regardless of Resource.
FORBIDDEN_ACTIONS = frozenset({
    "*",
    "iam:*",
    "iam:passrole",
    "iam:createaccesskey",
    "iam:updateaccesskey",
    "iam:putuserpolicy",
    "iam:putgrouppolicy",
    "iam:putrolepolicy",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:updateassumerolepolicy",
    "sts:*",
    "sts:assumerole",
    "organizations:*",
})


def parse_args() -> argparse.Namespace:
    """Parse and return the command-line arguments."""
    parser = argparse.ArgumentParser(description="Customer-managed policies validation")
    parser.add_argument(
        "--policies-folder",
        dest="policies_folder",
        required=True,
        help="Folder containing customer-managed policy JSON files.",
    )
    parser.add_argument(
        "--assignments-folder",
        dest="assignments_folder",
        required=False,
        help="Folder containing assignment JSON files (reserved for future cross-checks).",
    )
    parser.add_argument(
        "--access-analyzer-region",
        dest="access_analyzer_region",
        required=False,
        default=os.environ.get("AWS_REGION") or os.environ.get("REGION") or "us-east-1",
        help="AWS region for the Access Analyzer client (default: $AWS_REGION / us-east-1).",
    )
    parser.add_argument(
        "--skip-access-analyzer",
        dest="skip_access_analyzer",
        action="store_true",
        default=os.environ.get("SKIP_ACCESS_ANALYZER", "").lower() in ("1", "true", "yes"),
        help=(
            "Skip the IAM Access Analyzer ValidatePolicy call. "
            "INTENDED FOR LOCAL DEVELOPMENT ONLY. Must not be set in the pipeline."
        ),
    )
    return parser.parse_args()


def load_policy_files(folder: str) -> dict:
    """Load every *.json file in folder and return a {filename: dict} mapping.

    Returns an empty dict if the folder does not exist (caller decides if that is an error).
    Re-raises json.JSONDecodeError and OSError so the pipeline stage fails loudly.
    """
    policies: dict = {}

    if not os.path.isdir(folder):
        LOG.warning("Folder '%s' does not exist. Skipping policy loading.", folder)
        return policies

    for entry in os.listdir(folder):
        if not entry.endswith(".json"):
            continue
        path = os.path.join(folder, entry)
        try:
            with open(path, "r", encoding="utf-8") as file_handle:
                policies[entry] = json.load(file_handle)
            LOG.info("Policy '%s' loaded successfully.", entry)
        except json.JSONDecodeError as exc:
            LOG.error("Invalid JSON in file '%s': %s", entry, exc)
            raise
        except OSError as exc:
            LOG.error("Cannot read file '%s': %s", entry, exc)
            raise

    LOG.info("Customer-managed policies successfully loaded from repository files.")
    return policies


def validate_unique_policy_name(policies: dict) -> None:
    """Raise ValueError if two or more policy templates share the same PolicyName."""
    if not policies:
        raise ValueError("No policy files were loaded; nothing to validate.")

    names = [doc.get("PolicyName") for doc in policies.values() if "PolicyName" in doc]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        LOG.error("Customer-managed policies share the same PolicyName: %s", duplicates)
        raise ValueError(f"Duplicate PolicyName values: {duplicates}")

    LOG.info("No customer-managed policies share the same PolicyName.")


def validate_policy_paths(policies: dict) -> None:
    """Raise ValueError if any policy template has an invalid Path.

    Defaults to '/' when the field is absent, matching IAM behavior. The path
    is interpolated directly into the policy ARN at deploy time, so an invalid
    value would either fail late in IAM or silently produce a surprising ARN.
    """
    errors: list = []
    for filename, doc in policies.items():
        path = doc.get("Path", "/")

        if not isinstance(path, str):
            errors.append(
                f"{filename}: Path must be a string, got {type(path).__name__}"
            )
            continue
        if len(path) > POLICY_PATH_MAX_LENGTH:
            errors.append(
                f"{filename}: Path is {len(path)} chars (max {POLICY_PATH_MAX_LENGTH})"
            )
            continue
        if not POLICY_PATH_PATTERN.match(path):
            errors.append(
                f"{filename}: invalid Path '{path}' "
                f"(must start and end with '/', allowed chars: A-Z a-z 0-9 . _ = + -, no empty segments)"
            )

    if errors:
        for err in errors:
            LOG.error(err)
        raise ValueError(
            f"Invalid Path field in {len(errors)} policy template(s)."
        )

    LOG.info("All policy Path values are valid.")


def load_assignment_files(folder: str) -> dict:
    """Load every *.json file in folder and return a {filename: dict} mapping.

    Mirrors load_policy_files but for assignment templates. Returns an
    empty dict if the folder does not exist.
    """
    assignments: dict = {}

    if not os.path.isdir(folder):
        LOG.warning("Folder '%s' does not exist. Skipping assignment loading.", folder)
        return assignments

    for entry in os.listdir(folder):
        if not entry.endswith(".json"):
            continue
        path = os.path.join(folder, entry)
        try:
            with open(path, "r", encoding="utf-8") as file_handle:
                assignments[entry] = json.load(file_handle)
            LOG.info("Assignment '%s' loaded successfully.", entry)
        except json.JSONDecodeError as exc:
            LOG.error("Invalid JSON in file '%s': %s", entry, exc)
            raise
        except OSError as exc:
            LOG.error("Cannot read file '%s': %s", entry, exc)
            raise

    LOG.info("Customer-managed assignments successfully loaded from repository files.")
    return assignments


def validate_target_account_ids(assignments: dict) -> None:
    """Raise ValueError if any Target entry is not a 12-digit account ID.

    Account IDs that fall through here lead to confusing AccessDenied errors at
    runtime (when the cross-account role lookup fails). Catching them at
    template-validation time gives the operator a clear, file-scoped error
    message instead.
    """
    errors: list = []

    for filename, data in assignments.items():
        if not isinstance(data, dict):
            errors.append(
                f"{filename}: top-level JSON must be an object, got {type(data).__name__}"
            )
            continue

        for idx, assignment in enumerate(data.get("Assignments", [])):
            sid = assignment.get("SID", f"index-{idx}")
            targets = assignment.get("Target", [])

            if not isinstance(targets, list):
                errors.append(
                    f"{filename}#{sid}: Target must be a list, got {type(targets).__name__}"
                )
                continue

            for account_id in targets:
                if not isinstance(account_id, str):
                    errors.append(
                        f"{filename}#{sid}: Target entry must be a string, "
                        f"got {type(account_id).__name__}: {account_id!r}"
                    )
                elif not ACCOUNT_ID_PATTERN.match(account_id):
                    errors.append(
                        f"{filename}#{sid}: invalid account ID {account_id!r} "
                        f"(must be exactly 12 digits, no leading/trailing whitespace)"
                    )

    if errors:
        for err in errors:
            LOG.error(err)
        raise ValueError(
            f"Invalid Target account ID in {len(errors)} entry(ies)."
        )

    LOG.info("All Target account IDs are valid.")


# --------------------------------------------------------------------------- #
# PolicyDocument structural validation
# --------------------------------------------------------------------------- #


def _iter_statements(policy_document):
    """Yield (index, statement) pairs for each statement in the document.

    Statement may be a single object or a list of objects per the IAM
    spec. Non-dict statements raise ValueError with a precise message.
    """
    stmt = policy_document.get("Statement")
    if isinstance(stmt, dict):
        yield 0, stmt
        return
    if isinstance(stmt, list):
        for idx, item in enumerate(stmt):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Statement[{idx}] must be an object, got {type(item).__name__}"
                )
            yield idx, item
        return
    raise ValueError(
        f"PolicyDocument.Statement must be an object or a list of objects, "
        f"got {type(stmt).__name__ if stmt is not None else 'missing'}"
    )


def _as_list(value):
    """Normalize an IAM field that may be a string or a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _service_prefix(action: str) -> str:
    """Return the lowercase service prefix of an IAM action (text before ':')."""
    if ":" not in action:
        return ""
    return action.split(":", 1)[0].strip().lower()


def validate_policy_documents(policies: dict) -> None:
    """Perform local structural checks on every PolicyDocument.

    Rules enforced (fail-closed; errors across every file are aggregated):

    * PolicyDocument must be present and a JSON object.
    * Version must be "2012-10-17".
    * Statement must be an object or a non-empty list of objects.
    * Each statement must have an Effect of exactly "Allow" or "Deny".
    * NotAction and NotResource are refused outright (they invert the
      guardrail and are rarely what the author intended).
    * Action must be a non-empty string or list of strings; every value
      matches 'service:Verb' / 'service:*' / '*' and is not in
      FORBIDDEN_ACTIONS.
    * For Effect: Allow statements, service-wide wildcards (service:*)
      are refused for SENSITIVE_SERVICES, and Resource: "*" is
      refused for SENSITIVE_SERVICES.
    * The minified policy-document size must not exceed
      POLICY_DOCUMENT_MAX_LENGTH (IAM's hard limit).

    Raises ValueError with an aggregated message when any check fails.
    """
    errors: list = []

    for filename, doc in policies.items():
        file_errors: list = []

        if not isinstance(doc, dict):
            errors.append(f"{filename}: top-level JSON must be an object")
            continue

        policy_document = doc.get("PolicyDocument")
        if policy_document is None:
            errors.append(f"{filename}: missing required field 'PolicyDocument'")
            continue
        if not isinstance(policy_document, dict):
            errors.append(
                f"{filename}: PolicyDocument must be a JSON object, "
                f"got {type(policy_document).__name__}"
            )
            continue

        version = policy_document.get("Version")
        if version not in ALLOWED_POLICY_VERSIONS:
            file_errors.append(
                f"PolicyDocument.Version must be one of "
                f"{sorted(ALLOWED_POLICY_VERSIONS)}, got {version!r}"
            )

        # Enforce IAM's 6144-char managed-policy size limit on the minified
        # body. json.dumps with separators=(',',':') matches how the deploy
        # script serializes the document before iam:CreatePolicy.
        try:
            serialized = json.dumps(policy_document, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            file_errors.append(f"PolicyDocument is not JSON-serializable: {exc}")
            serialized = ""
        if len(serialized) > POLICY_DOCUMENT_MAX_LENGTH:
            file_errors.append(
                f"PolicyDocument is {len(serialized)} chars after minification "
                f"(IAM limit is {POLICY_DOCUMENT_MAX_LENGTH})"
            )

        try:
            statements = list(_iter_statements(policy_document))
        except ValueError as exc:
            file_errors.append(str(exc))
            statements = []

        if (
            "Statement" in policy_document
            and not statements
            and isinstance(policy_document.get("Statement"), list)
        ):
            file_errors.append("PolicyDocument.Statement must not be empty")

        for idx, statement in statements:
            effect = statement.get("Effect")
            if effect not in ("Allow", "Deny"):
                file_errors.append(
                    f"Statement[{idx}].Effect must be 'Allow' or 'Deny', got {effect!r}"
                )

            if "NotAction" in statement:
                file_errors.append(
                    f"Statement[{idx}] uses 'NotAction' which is refused by policy "
                    f"(inverts the allowlist; use explicit 'Action' instead)"
                )
            if "NotResource" in statement:
                file_errors.append(
                    f"Statement[{idx}] uses 'NotResource' which is refused by policy "
                    f"(inverts the resource scope; use explicit 'Resource' instead)"
                )

            actions = _as_list(statement.get("Action"))
            if "Action" not in statement:
                file_errors.append(f"Statement[{idx}] is missing required 'Action'")
            elif not actions:
                file_errors.append(f"Statement[{idx}].Action must not be empty")

            for action in actions:
                if not isinstance(action, str):
                    file_errors.append(
                        f"Statement[{idx}].Action entries must be strings, "
                        f"got {type(action).__name__}: {action!r}"
                    )
                    continue
                normalized = action.strip().lower()
                if not ACTION_PATTERN.match(action.strip()):
                    file_errors.append(
                        f"Statement[{idx}] has malformed Action {action!r} "
                        f"(expected 'service:Verb', 'service:*' or '*')"
                    )
                    continue
                if normalized in FORBIDDEN_ACTIONS:
                    file_errors.append(
                        f"Statement[{idx}] uses forbidden Action {action!r} "
                        f"(admin-equivalent or direct privilege-escalation primitive)"
                    )
                    continue
                # Service-wide wildcard against a sensitive service.
                if effect == "Allow" and normalized.endswith(":*"):
                    svc = _service_prefix(normalized)
                    if svc in SENSITIVE_SERVICES:
                        file_errors.append(
                            f"Statement[{idx}] uses service-wide wildcard {action!r} "
                            f"on sensitive service '{svc}' (refused for Effect: Allow)"
                        )

            resources = _as_list(statement.get("Resource"))
            if "Resource" not in statement:
                file_errors.append(f"Statement[{idx}] is missing required 'Resource'")

            for resource in resources:
                if not isinstance(resource, str):
                    file_errors.append(
                        f"Statement[{idx}].Resource entries must be strings, "
                        f"got {type(resource).__name__}: {resource!r}"
                    )

            # Resource: "*" combined with Allow on a sensitive service is
            # refused outright. We flag the (service, resource='*') pair so
            # a narrow Deny on "*" still passes.
            if effect == "Allow" and any(
                r == "*" for r in resources if isinstance(r, str)
            ):
                for action in actions:
                    if not isinstance(action, str):
                        continue
                    svc = _service_prefix(action.strip().lower())
                    if svc and svc in SENSITIVE_SERVICES:
                        file_errors.append(
                            f"Statement[{idx}] has Effect: Allow with Resource: '*' "
                            f"for sensitive service '{svc}' (action {action!r})"
                        )

        for err in file_errors:
            errors.append(f"{filename}: {err}")

    if errors:
        for err in errors:
            LOG.error(err)
        raise ValueError(
            f"PolicyDocument validation failed with {len(errors)} issue(s)."
        )

    LOG.info("All PolicyDocument bodies passed structural validation.")


# --------------------------------------------------------------------------- #
# IAM Access Analyzer ValidatePolicy
# --------------------------------------------------------------------------- #


def validate_policies_with_access_analyzer(
    policies: dict,
    *,
    region: str,
    skip: bool = False,
) -> None:
    """Call accessanalyzer:ValidatePolicy on every PolicyDocument.

    Fails the build when any finding has findingType ERROR or
    SECURITY_WARNING. SUGGESTION and WARNING findings are logged
    but non-fatal.

    When skip is true the call is logged and bypassed (intended for local
    development only). When boto3 or the accessanalyzer client is
    unavailable and skip is false, this function raises so the pipeline
    fails loudly instead of silently skipping the control the README
    advertises.
    """
    if skip:
        LOG.warning(
            "IAM Access Analyzer ValidatePolicy explicitly skipped "
            "(--skip-access-analyzer / SKIP_ACCESS_ANALYZER). "
            "This flag MUST NOT be set in the pipeline."
        )
        return

    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "boto3/botocore are required for IAM Access Analyzer validation. "
            "Install them (see requirements.txt) or re-run with "
            "--skip-access-analyzer for offline development only."
        ) from exc

    client = boto3.client("accessanalyzer", region_name=region)

    blocking: list = []
    for filename, doc in policies.items():
        policy_document = doc.get("PolicyDocument") if isinstance(doc, dict) else None
        if not isinstance(policy_document, dict):
            # Already reported by validate_policy_documents; skip gracefully.
            continue
        body = json.dumps(policy_document, separators=(",", ":"))
        findings: list = []
        try:
            paginator = client.get_paginator("validate_policy")
            pages = paginator.paginate(
                policyDocument=body,
                policyType="IDENTITY_POLICY",
            )
            for page in pages:
                findings.extend(page.get("findings", []))
        except (BotoCoreError, ClientError) as exc:
            raise RuntimeError(
                f"accessanalyzer:ValidatePolicy failed for '{filename}': {exc}"
            ) from exc

        for finding in findings:
            ftype = finding.get("findingType", "")
            code = finding.get("issueCode", "")
            details = finding.get("findingDetails", "")
            msg = f"{filename}: [{ftype}] {code} - {details}"
            if ftype in ("ERROR", "SECURITY_WARNING"):
                LOG.error(msg)
                blocking.append(msg)
            else:
                LOG.warning(msg)

    if blocking:
        raise ValueError(
            f"IAM Access Analyzer reported {len(blocking)} blocking "
            f"finding(s) (ERROR/SECURITY_WARNING)."
        )

    LOG.info("All PolicyDocument bodies passed IAM Access Analyzer ValidatePolicy.")


def main() -> int:
    """Run all template-validation checks. Return 0 on success, 1 on failure."""
    logging.basicConfig(
        format="%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d:%H:%M:%S",
        level=logging.INFO,
    )

    args = parse_args()

    try:
        policies = load_policy_files(args.policies_folder)
        if not policies:
            LOG.error("No policies found in folder '%s'. Exiting.", args.policies_folder)
            return 1

        validate_unique_policy_name(policies)
        validate_policy_paths(policies)
        validate_policy_documents(policies)
        validate_policies_with_access_analyzer(
            policies,
            region=args.access_analyzer_region,
            skip=args.skip_access_analyzer,
        )

        # Validate Target account IDs only if the assignments folder was given.
        # Loud warning if missing so it does not silently skip.
        if args.assignments_folder:
            assignments = load_assignment_files(args.assignments_folder)
            if assignments:
                validate_target_account_ids(assignments)
            else:
                LOG.warning(
                    "Assignments folder '%s' has no JSON files; "
                    "skipping Target account validation.",
                    args.assignments_folder,
                )
        else:
            LOG.warning(
                "--assignments-folder not provided; "
                "skipping Target account validation."
            )
    except (ValueError, RuntimeError, json.JSONDecodeError, OSError) as exc:
        LOG.error("Validation failed: %s", exc)
        return 1

    LOG.info("All customer-managed policies validated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
