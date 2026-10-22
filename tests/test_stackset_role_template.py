# SPDX-License-Identifier: MIT
"""Structural tests for cfn/cx-mng-stackset-deploy-role.yaml.

These assert the security invariants of the deploy-role grant:

* Destructive/mutating IAM actions (DeletePolicy, DeletePolicyVersion,
  CreatePolicyVersion, UntagPolicy) must be gated by the
  ``aws:ResourceTag/cx-mng: true`` condition, so even a buggy or tampered
  deploy script cannot delete/modify policies the pipeline does not own.
* Creation-time actions (CreatePolicy, and TagPolicy when applied at create
  time) must be gated by ``aws:RequestTag/cx-mng: true`` instead - using
  ``aws:ResourceTag`` here is a well-known footgun because a brand-new
  policy has no tags yet, so ``aws:ResourceTag`` can never be satisfied and
  the deploy flow would leave untagged, unmanageable policies behind.

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

# Mutating/destructive actions that MUST stay gated by the resource-tag
# condition. iam:TagPolicy is deliberately NOT in this set: TagPolicy is
# also used at create time (where only aws:RequestTag works), so the role
# grants it under both the request-tag and resource-tag statements.
DESTRUCTIVE_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:DeletePolicy",
    "iam:DeletePolicyVersion",
    "iam:UntagPolicy",
}

# Actions that are used to create (or atomically tag at creation time) new
# policies. These cannot be gated by aws:ResourceTag because the resource
# does not exist / has no tags yet; they must be gated by aws:RequestTag.
CREATION_ACTIONS = {
    "iam:CreatePolicy",
    "iam:TagPolicy",
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


def _has_resource_tag_condition(statement) -> bool:
    cond = statement.get("Condition", {})
    string_equals = cond.get("StringEquals", {})
    return string_equals.get("aws:ResourceTag/cx-mng") == "true"


def _has_request_tag_condition(statement) -> bool:
    cond = statement.get("Condition", {})
    string_equals = cond.get("StringEquals", {})
    return string_equals.get("aws:RequestTag/cx-mng") == "true"


def test_destructive_actions_require_resource_tag_condition(role_statements):
    """Every destructive IAM action must live in a statement gated by the resource tag."""
    for statement in role_statements:
        actions = _actions(statement)
        destructive_here = actions & DESTRUCTIVE_ACTIONS
        if destructive_here:
            assert _has_resource_tag_condition(statement), (
                f"Destructive actions {destructive_here} are NOT gated by the "
                f"aws:ResourceTag/cx-mng=true condition (Sid={statement.get('Sid')})"
            )


def test_no_destructive_action_in_unconditioned_statement(role_statements):
    """No statement WITHOUT the resource-tag condition may include a destructive action."""
    for statement in role_statements:
        if _has_resource_tag_condition(statement):
            continue
        leaked = _actions(statement) & DESTRUCTIVE_ACTIONS
        assert not leaked, (
            f"Statement Sid={statement.get('Sid')} allows destructive actions "
            f"{leaked} without the cx-mng resource-tag condition"
        )


def test_create_policy_requires_request_tag_condition(role_statements):
    """iam:CreatePolicy must be gated by aws:RequestTag/cx-mng=true.

    Using aws:ResourceTag here would make the grant unusable (the policy has
    no tags yet). Leaving CreatePolicy unconditional would allow the pipeline
    to create policies it later cannot tag/manage/delete.
    """
    create_statements = [
        s for s in role_statements if "iam:CreatePolicy" in _actions(s)
    ]
    assert create_statements, "iam:CreatePolicy permission is missing entirely"
    for statement in create_statements:
        assert _has_request_tag_condition(statement), (
            f"iam:CreatePolicy in Sid={statement.get('Sid')} is not gated by "
            "aws:RequestTag/cx-mng=true; the pipeline could create policies "
            "it cannot subsequently tag or manage."
        )
        assert not _has_resource_tag_condition(statement), (
            f"iam:CreatePolicy in Sid={statement.get('Sid')} is gated by "
            "aws:ResourceTag/cx-mng=true, which can never be satisfied at "
            "create time (the policy has no tags yet)."
        )


def test_tag_policy_at_create_time_uses_request_tag(role_statements):
    """iam:TagPolicy must be available with the aws:RequestTag condition.

    TagPolicy is called both at create time (via Tags= on CreatePolicy, which
    IAM authorizes against aws:RequestTag) and against already-tagged
    policies on later updates (authorized against aws:ResourceTag). The role
    must grant it under at least the request-tag statement, otherwise the
    atomic create+tag path fails with AccessDenied.
    """
    tag_statements = [
        s for s in role_statements if "iam:TagPolicy" in _actions(s)
    ]
    assert tag_statements, "iam:TagPolicy permission is missing entirely"
    assert any(
        _has_request_tag_condition(s) for s in tag_statements
    ), (
        "iam:TagPolicy is not gated by aws:RequestTag/cx-mng=true anywhere; "
        "atomic create+tag calls on new policies will be denied."
    )


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
