# SPDX-License-Identifier: MIT
"""Structural tests for cfn/cx-mng-stackset-deploy-role.yaml.

These assert the security invariant introduced by the least-privilege split
(MEDIUM-4): destructive/mutating IAM actions must be gated by the
``aws:ResourceTag/cx-mng: true`` condition, so even a buggy or tampered deploy
script cannot delete/modify policies the pipeline does not own.

The test parses the CloudFormation YAML with a loader that ignores the
intrinsic ``!Sub`` / ``!Ref`` tags (we only care about the policy structure,
not the resolved values).
"""

from pathlib import Path

import pytest
import yaml


TEMPLATE = (
    Path(__file__).resolve().parent.parent
    / "cfn"
    / "cx-mng-stackset-deploy-role.yaml"
)

# Actions that must NEVER be allowed without the cx-mng:true tag condition.
DESTRUCTIVE_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:DeletePolicy",
    "iam:DeletePolicyVersion",
    "iam:TagPolicy",
    "iam:UntagPolicy",
}


class _CfnLoader(yaml.SafeLoader):
    """YAML loader that tolerates CloudFormation ``!Sub`` / ``!Ref`` tags."""


def _ignore_unknown(loader, tag_suffix, node):  # noqa: ANN001
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CfnLoader.add_multi_constructor("!", _ignore_unknown)


@pytest.fixture(scope="module")
def role_statements() -> list:
    """Return the inline policy statements of DeployCustomerManagedPolicyRole."""
    with open(TEMPLATE, "r", encoding="utf-8") as fh:
        doc = yaml.load(fh, Loader=_CfnLoader)
    role = doc["Resources"]["DeployCustomerManagedPolicyRole"]
    inline_policies = role["Properties"]["Policies"]
    statements = []
    for policy in inline_policies:
        statements.extend(policy["PolicyDocument"]["Statement"])
    return statements


def _actions(statement) -> set:
    action = statement.get("Action", [])
    return set(action if isinstance(action, list) else [action])


def _has_cxmng_tag_condition(statement) -> bool:
    cond = statement.get("Condition", {})
    string_equals = cond.get("StringEquals", {})
    return string_equals.get("aws:ResourceTag/cx-mng") == "true"


def test_destructive_actions_require_cxmng_tag_condition(role_statements):
    """Every destructive IAM action in an Allow must be gated by the tag."""
    for statement in role_statements:
        if statement.get("Effect") != "Allow":
            # Deny statements are a *stronger* guard, not a weaker one, and
            # may legitimately scope on request-side conditions instead of
            # aws:ResourceTag/cx-mng.
            continue
        actions = _actions(statement)
        destructive_here = actions & DESTRUCTIVE_ACTIONS
        if destructive_here:
            assert _has_cxmng_tag_condition(statement), (
                f"Destructive actions {destructive_here} are NOT gated by the "
                f"aws:ResourceTag/cx-mng=true condition (Sid={statement.get('Sid')})"
            )


def test_no_destructive_action_in_unconditioned_statement(role_statements):
    """No Allow statement without the tag condition may include a destructive action."""
    for statement in role_statements:
        if statement.get("Effect") != "Allow":
            continue
        if _has_cxmng_tag_condition(statement):
            continue
        leaked = _actions(statement) & DESTRUCTIVE_ACTIONS
        assert not leaked, (
            f"Statement Sid={statement.get('Sid')} allows destructive actions "
            f"{leaked} without the cx-mng tag condition"
        )


def test_create_policy_is_allowed_without_tag_condition(role_statements):
    """iam:CreatePolicy must remain usable (policy has no tag at create time)."""
    create_statements = [
        s for s in role_statements if "iam:CreatePolicy" in _actions(s)
    ]
    assert create_statements, "iam:CreatePolicy permission is missing entirely"
    # At least one CreatePolicy statement must NOT carry the tag condition,
    # otherwise creation could never succeed.
    assert any(
        not _has_cxmng_tag_condition(s) for s in create_statements
    ), "iam:CreatePolicy is gated by a tag condition it can never satisfy at create time"


def test_no_wildcard_resource_on_destructive_statements(role_statements):
    """Destructive statements must scope Resource to the account, not '*'."""
    for statement in role_statements:
        if _actions(statement) & DESTRUCTIVE_ACTIONS:
            resource = statement.get("Resource")
            resources = resource if isinstance(resource, list) else [resource]
            assert "*" not in resources, (
                f"Destructive statement Sid={statement.get('Sid')} uses "
                f"Resource '*' instead of an account-scoped ARN"
            )


# --------------------------------------------------------------------------- #
# Ownership-tag preservation — added to defeat the repo-controlled TagPolicy
# attack where a template declaring ``cx-mng: false`` orphans a managed policy.
# --------------------------------------------------------------------------- #


def _requires_request_cxmng_true(statement) -> bool:
    cond = statement.get("Condition", {})
    for operator in ("StringEquals", "StringEqualsIfExists"):
        if cond.get(operator, {}).get("aws:RequestTag/cx-mng") == "true":
            return True
    return False


def _denies_untag_of_cxmng(statement) -> bool:
    if statement.get("Effect") != "Deny":
        return False
    if "iam:UntagPolicy" not in _actions(statement):
        return False
    cond = statement.get("Condition", {})
    for operator, body in cond.items():
        if "StringEquals" not in operator:
            continue
        keys = body.get("aws:TagKeys", [])
        if isinstance(keys, str):
            keys = [keys]
        if "cx-mng" in keys:
            return True
    return False


def test_tag_policy_requires_request_cxmng_true(role_statements):
    """Every Allow granting iam:TagPolicy must forbid overwriting cx-mng to anything but 'true'."""
    tag_statements = [
        s for s in role_statements
        if s.get("Effect") == "Allow" and "iam:TagPolicy" in _actions(s)
    ]
    assert tag_statements, "iam:TagPolicy permission is missing entirely"
    for statement in tag_statements:
        assert _requires_request_cxmng_true(statement), (
            f"Statement Sid={statement.get('Sid')} grants iam:TagPolicy "
            f"without aws:RequestTag/cx-mng=true; a repo-controlled TagPolicy "
            f"call could overwrite the ownership tag."
        )


def test_untag_cxmng_is_explicitly_denied(role_statements):
    """An explicit Deny must block iam:UntagPolicy whose TagKeys includes cx-mng."""
    assert any(_denies_untag_of_cxmng(s) for s in role_statements), (
        "No explicit Deny guards against removing the cx-mng ownership tag "
        "via iam:UntagPolicy."
    )
