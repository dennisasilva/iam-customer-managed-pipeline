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

Runs as part of the pipeline ``TemplateValidation`` stage. Currently performs:

* JSON syntax validation of every ``*.json`` file in the policies folder.
* Uniqueness check on the ``PolicyName`` field across all policy templates.

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

# Tag key that the pipeline reserves for its own ownership marker. Repository
# templates must never declare a Tag with this key - if they could, a single
# commit could flip the ownership tag off during an update and permanently
# move the policy out of the deploy role's authority (the role's IAM policy
# gates destructive actions on ``aws:ResourceTag/cx-mng=true``).
RESERVED_TAG_KEY = "cx-mng"

# AWS account IDs are exactly 12 digits. Anything else here (typos, trailing
# whitespace, formatted numbers from spreadsheets, missing leading zeros) leads
# to confusing AccessDenied errors at runtime when assume_role fails.
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")


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


def validate_policy_tags(policies: dict) -> None:
    """Raise ``ValueError`` if any policy template declares the reserved tag key.

    The ``cx-mng`` key is written by the deploy script to mark a policy as
    managed by this pipeline; allowing a template to set the same key lets a
    repository commit overwrite the ownership tag and permanently remove the
    policy from the pipeline's and the deploy role's authority. Reject such
    templates at validation time so the issue surfaces before any apply-mode
    stage runs.
    """
    errors: list = []
    for filename, doc in policies.items():
        tags = doc.get("Tags", [])
        if tags is None:
            continue
        if not isinstance(tags, list):
            errors.append(
                f"{filename}: Tags must be a list, got {type(tags).__name__}"
            )
            continue
        for idx, tag in enumerate(tags):
            if not isinstance(tag, dict):
                errors.append(
                    f"{filename}: Tags[{idx}] must be an object, "
                    f"got {type(tag).__name__}"
                )
                continue
            if tag.get("Key") == RESERVED_TAG_KEY:
                errors.append(
                    f"{filename}: Tags[{idx}] uses reserved key "
                    f"{RESERVED_TAG_KEY!r}; this key is managed by the "
                    f"pipeline and cannot be set from a template."
                )

    if errors:
        for err in errors:
            LOG.error(err)
        raise ValueError(
            f"Invalid Tags in {len(errors)} policy template entry(ies)."
        )

    LOG.info("All policy Tags values are valid.")


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
        validate_policy_tags(policies)

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
