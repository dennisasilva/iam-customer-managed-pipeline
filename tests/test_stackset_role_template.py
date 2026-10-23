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


def _has_cxmng_request_tag_condition(statement) -> bool:
    cond = statement.get("Condition", {})
    string_equals = cond.get("StringEquals", {})
    return string_equals.get("aws:RequestTag/cx-mng") == "true"


def _forbids_removing_cxmng_tag(statement) -> bool:
    """Return True iff the statement forbids UntagPolicy from touching cx-mng."""
    cond = statement.get("Condition", {})
    for_all = cond.get("ForAllValues:StringNotEquals", {})
    tag_keys = for_all.get("aws:TagKeys", [])
    if isinstance(tag_keys, str):
        tag_keys = [tag_keys]
    return "cx-mng" in set(tag_keys)


def test_destructive_actions_require_cxmng_tag_condition(role_statements):
    """Every destructive IAM action must live in a statement gated by the tag."""
    for statement in role_statements:
        actions = _actions(statement)
        destructive_here = actions & DESTRUCTIVE_ACTIONS
        if destructive_here:
            assert _has_cxmng_tag_condition(statement), (
                f"Destructive actions {destructive_here} are NOT gated by the "
                f"aws:ResourceTag/cx-mng=true condition (Sid={statement.get('Sid')})"
            )


def test_no_destructive_action_in_unconditioned_statement(role_statements):
    """No statement WITHOUT the tag condition may include a destructive action."""
    for statement in role_statements:
        if _has_cxmng_tag_condition(statement):
            continue
        leaked = _actions(statement) & DESTRUCTIVE_ACTIONS
        assert not leaked, (
            f"Statement Sid={statement.get('Sid')} allows destructive actions "
            f"{leaked} without the cx-mng tag condition"
        )


def test_create_policy_is_allowed_without_tag_condition(role_statements):
    """iam:CreatePolicy must remain usable (policy has no ResourceTag at create time)."""
    create_statements = [
        s for s in role_statements if "iam:CreatePolicy" in _actions(s)
    ]
    assert create_statements, "iam:CreatePolicy permission is missing entirely"
    # At least one CreatePolicy statement must NOT carry the ResourceTag
    # condition, otherwise creation could never succeed (the policy does not
    # exist yet so aws:ResourceTag/* is absent at authorization time).
    assert any(
        not _has_cxmng_tag_condition(s) for s in create_statements
    ), "iam:CreatePolicy is gated by a ResourceTag condition it can never satisfy at create time"


def test_create_policy_is_gated_by_request_tag(role_statements):
    """iam:CreatePolicy must require aws:RequestTag/cx-mng=true at create time.

    This is the ownership-boundary invariant: the deploy role may only mint
    policies whose creation request already carries cx-mng:true, so every
    policy born inside the pipeline is immediately inside the cx-mng
    management boundary (updates/deletes gated by aws:ResourceTag/cx-mng=true
    continue to work on them). Without this gate, newly created policies
    could end up permanently un-tagged and therefore outside the pipeline's
    reach — the drift this test enforces against.
    """
    create_statements = [
        s for s in role_statements if "iam:CreatePolicy" in _actions(s)
    ]
    assert create_statements, "iam:CreatePolicy permission is missing entirely"
    # EVERY CreatePolicy allow statement must carry the aws:RequestTag/cx-mng
    # gate: otherwise a caller could create a policy without the ownership
    # tag and escape pipeline management.
    for stmt in create_statements:
        assert _has_cxmng_request_tag_condition(stmt), (
            f"iam:CreatePolicy statement Sid={stmt.get('Sid')} is not gated by "
            f"StringEquals aws:RequestTag/cx-mng=true"
        )


def test_untag_policy_cannot_remove_cxmng_key(role_statements):
    """iam:UntagPolicy must be forbidden from removing the cx-mng ownership key.

    Even on a policy already tagged cx-mng:true, the role must not be able to
    untag that key, otherwise it could strip ownership and escape the
    management boundary from the inside.
    """
    untag_statements = [
        s for s in role_statements if "iam:UntagPolicy" in _actions(s)
    ]
    assert untag_statements, "iam:UntagPolicy permission is missing entirely"
    for stmt in untag_statements:
        assert _forbids_removing_cxmng_tag(stmt), (
            f"iam:UntagPolicy statement Sid={stmt.get('Sid')} does not forbid "
            f"removal of the cx-mng key via ForAllValues:StringNotEquals aws:TagKeys"
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
