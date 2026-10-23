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

Runs as part of the pipeline ``TemplateValidation`` stage. Performs:

* JSON syntax validation of every ``*.json`` file in the policies folder.
* Uniqueness check on the ``PolicyName`` field across all policy templates.
* ``Path`` field well-formedness.
* ``Target`` 12-digit account-ID well-formedness for assignment JSONs.
* Policy-document privilege-escalation denylist (``iam:*``, ``Action: "*"``,
  ``NotAction``/``NotResource`` in Allow, sensitive-service wildcards on
  ``Resource: "*"``, and known PassRole/AssumeRole/Attach* escalation actions).
  The deploy stage re-runs this same check as defense in depth.

Arguments:
    --policies-folder:    Folder containing customer-managed policy JSON files.
    --assignments-folder: Folder containing assignment JSON files (reserved for
                          future cross-checks; accepted but not used yet).
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
# to confusing AccessDenied errors at runtime when assume_role fails.
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")


# --------------------------------------------------------------------------- #
# Policy-document denylist
# --------------------------------------------------------------------------- #
#
# These checks run before any IAM mutation. They are intentionally narrow: the
# pipeline exists to deploy declarative policy JSON, so we only reject patterns
# that are indistinguishable from an attacker trying to mint account-takeover
# primitives via a repository commit (CWE-267). Legitimate scoped-wildcard
# patterns such as ``ec2:*SecurityGroup*`` or ``fis:*`` on ``Resource: "*"``
# are intentionally allowed; only *fully* wildcard IAM/STS/Organizations etc.
# or explicit privilege-escalation action names are rejected.
#
# Service prefixes that must never be combined with ``Resource: "*"`` because
# they control identities, auth, keys, logging, or guardrails. Scoping these
# to a concrete ARN is the whole point of a customer-managed policy.
SENSITIVE_WILDCARD_RESOURCE_SERVICES = frozenset({
    "iam",
    "sts",
    "organizations",
    "account",
    "kms",
    "secretsmanager",
    "ssm",
    "cloudtrail",
    "config",
    "guardduty",
    "securityhub",
    "accessanalyzer",
    "identitystore",
    "sso",
    "sso-directory",
})

# Individual IAM/STS actions that are, on their own, a privilege-escalation
# primitive (either direct admin takeover or a well-known chain). An attacker
# who can land a managed policy carrying any of these on an unconstrained
# resource essentially owns every role in the target account the moment the
# policy is attached to a principal they influence.
PRIVILEGE_ESCALATION_ACTIONS = frozenset({
    "iam:*",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putrolepolicy",
    "iam:putuserpolicy",
    "iam:putgrouppolicy",
    "iam:createpolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:createrole",
    "iam:createuser",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:updateassumerolepolicy",
    "iam:passrole",
    "iam:addusertogroup",
    "iam:createservicelinkedrole",
    "sts:*",
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
})


def _as_list(value) -> list:
    """Return ``value`` as a list. Accepts ``None``, scalar, or list.

    IAM policy fields such as ``Action``/``Resource``/``Statement`` can be
    either a scalar or a list; normalizing here keeps the denylist logic
    simple and symmetric.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _action_service(action: str) -> str:
    """Return the service prefix of an IAM action string, lowercased.

    ``"iam:CreateRole"`` -> ``"iam"``. Returns ``""`` for malformed actions,
    which the caller treats as a validation error.
    """
    if not isinstance(action, str) or ":" not in action:
        return ""
    return action.split(":", 1)[0].strip().lower()


def _check_statement(filename: str, idx: int, statement) -> list:
    """Return a list of error messages for one Statement entry.

    Rules applied here mirror the mitigation in the finding:
      * Reject ``NotAction``/``NotResource`` in Allow statements (hard to reason
        about and the usual way wildcard-admin policies get smuggled in).
      * Reject ``Action: "*"`` (full wildcard).
      * Reject any action in :data:`PRIVILEGE_ESCALATION_ACTIONS`.
      * Reject ``Resource: "*"`` combined with an action from a service in
        :data:`SENSITIVE_WILDCARD_RESOURCE_SERVICES`.
      * Reject service-level wildcards (``"<svc>:*"``) on those same sensitive
        services even when ``Resource`` is not ``"*"``.
    """
    errors: list = []

    if not isinstance(statement, dict):
        return [f"{filename}#stmt-{idx}: Statement must be an object, got {type(statement).__name__}"]

    effect = statement.get("Effect", "Allow")
    # Deny statements that use NotAction/NotResource are a safe idiom (deny
    # everything except...) and have no privilege-escalation potential, so we
    # only enforce the denylist against Allow (the default when Effect is absent).
    if effect != "Allow":
        return errors

    sid = statement.get("Sid", f"stmt-{idx}")
    where = f"{filename}#{sid}"

    if "NotAction" in statement:
        errors.append(
            f"{where}: NotAction is not permitted in Allow statements "
            "(too easy to accidentally grant admin by exclusion)."
        )
    if "NotResource" in statement:
        errors.append(
            f"{where}: NotResource is not permitted in Allow statements "
            "(too easy to accidentally grant admin by exclusion)."
        )

    actions = _as_list(statement.get("Action"))
    resources = _as_list(statement.get("Resource"))
    has_star_resource = any(r == "*" for r in resources if isinstance(r, str))

    for action in actions:
        if not isinstance(action, str):
            errors.append(
                f"{where}: Action entry must be a string, got {type(action).__name__}: {action!r}"
            )
            continue

        normalized = action.strip().lower()

        if normalized == "*":
            errors.append(
                f"{where}: Action \"*\" is not permitted "
                "(unconstrained administrator access)."
            )
            continue

        if normalized in PRIVILEGE_ESCALATION_ACTIONS:
            errors.append(
                f"{where}: Action {action!r} is a known privilege-escalation "
                "primitive and is not permitted in customer-managed policies."
            )
            continue

        service = _action_service(normalized)
        if not service:
            errors.append(
                f"{where}: Action {action!r} is malformed (expected '<service>:<action>')."
            )
            continue

        # Service-level wildcard on a sensitive service, regardless of Resource.
        if normalized == f"{service}:*" and service in SENSITIVE_WILDCARD_RESOURCE_SERVICES:
            errors.append(
                f"{where}: Action {action!r} grants wildcard access to a "
                "security-sensitive service and is not permitted."
            )
            continue

        # Any action on a sensitive service combined with Resource: "*".
        if has_star_resource and service in SENSITIVE_WILDCARD_RESOURCE_SERVICES:
            errors.append(
                f"{where}: Action {action!r} on Resource \"*\" is not permitted "
                f"({service} actions must be scoped to a concrete ARN)."
            )

    return errors


def validate_policy_documents(policies: dict) -> None:
    """Reject policy documents that contain known privilege-escalation patterns.

    Raises ``ValueError`` listing every offending ``filename#Sid`` so the
    operator fixes all of them in one iteration instead of whack-a-mole.

    This is the content check the ``TemplateValidation`` stage promises in
    the README but did not implement; the deploy script also calls it before
    every ``iam:CreatePolicy``/``iam:CreatePolicyVersion`` as defense in depth.
    """
    all_errors: list = []

    for filename, doc in policies.items():
        if not isinstance(doc, dict):
            all_errors.append(
                f"{filename}: top-level JSON must be an object, got {type(doc).__name__}"
            )
            continue

        policy_document = doc.get("PolicyDocument")
        if not isinstance(policy_document, dict):
            all_errors.append(
                f"{filename}: PolicyDocument must be an object, "
                f"got {type(policy_document).__name__}"
            )
            continue

        statements = _as_list(policy_document.get("Statement"))
        if not statements:
            all_errors.append(
                f"{filename}: PolicyDocument.Statement is empty or missing."
            )
            continue

        for idx, statement in enumerate(statements):
            all_errors.extend(_check_statement(filename, idx, statement))

    if all_errors:
        for err in all_errors:
            LOG.error(err)
        raise ValueError(
            f"Rejected {len(all_errors)} privilege-escalation pattern(s) in policy templates."
        )

    LOG.info("All policy documents passed the privilege-escalation denylist.")


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
    return parser.parse_args()


def load_policy_files(folder: str) -> dict:
    """Load every ``*.json`` file in ``folder`` and return a ``{filename: dict}`` mapping.

    Returns an empty dict if the folder does not exist (caller decides if that is an error).
    Re-raises ``json.JSONDecodeError`` and ``OSError`` so the pipeline stage fails loudly.
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
    """Raise ``ValueError`` if two or more policy templates share the same PolicyName."""
    if not policies:
        raise ValueError("No policy files were loaded; nothing to validate.")

    names = [doc.get("PolicyName") for doc in policies.values() if "PolicyName" in doc]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        LOG.error("Customer-managed policies share the same PolicyName: %s", duplicates)
        raise ValueError(f"Duplicate PolicyName values: {duplicates}")

    LOG.info("No customer-managed policies share the same PolicyName.")


def validate_policy_paths(policies: dict) -> None:
    """Raise ``ValueError`` if any policy template has an invalid ``Path``.

    Defaults to ``/`` when the field is absent, matching IAM behavior. The path
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
    """Load every ``*.json`` file in ``folder`` and return a ``{filename: dict}`` mapping.

    Mirrors :func:`load_policy_files` but for assignment templates. Returns an
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
    """Raise ``ValueError`` if any ``Target`` entry is not a 12-digit account ID.

    Account IDs that fall through here lead to confusing AccessDenied errors at
    runtime (when ``sts.assume_role`` fails). Catching them at template-validation
    time gives the operator a clear, file-scoped error message instead.
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
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        LOG.error("Validation failed: %s", exc)
        return 1

    LOG.info("All customer-managed policies validated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
