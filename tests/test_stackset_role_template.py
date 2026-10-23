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
# Compartmentalization split (CWE-653): the pre-approval RoleValidation and
# DryRun stages must use a dedicated read-only role, and the mutation-capable
# deploy role must trust only the apply-stage principal.
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def resources() -> dict:
    with open(TEMPLATE, "r", encoding="utf-8") as fh:
        doc = yaml.load(fh, Loader=_CfnLoader)
    return doc["Resources"]


def _principal_arns(role: dict) -> list:
    trust = role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
    aws = trust["Principal"]["AWS"]
    return aws if isinstance(aws, list) else [aws]


def test_validate_role_exists_as_separate_resource(resources):
    """A dedicated read-only role must be defined for pre-approval stages."""
    assert "ValidateCustomerManagedPolicyRole" in resources, (
        "Missing read-only ValidateCustomerManagedPolicyRole — pre-approval "
        "stages would still receive mutation-capable credentials (CWE-653)."
    )


def test_deploy_role_trust_excludes_role_validation_principal(resources):
    """deploy-customer-managed-policy must NOT be assumable by RoleValidation / DryRun."""
    arns = _principal_arns(resources["DeployCustomerManagedPolicyRole"])
    for arn in arns:
        assert "-role-validation" not in arn, (
            "RoleValidation principal is still trusted by the mutation-capable "
            "deploy role (CWE-653). It must be moved to the read-only validate role."
        )
        assert "-dry-run" not in arn, (
            "DryRun principal is still trusted by the mutation-capable deploy role."
        )
    # Positive assertion: the apply-stage principal remains trusted.
    assert any("-customer-managed-policies" in a for a in arns), (
        "Apply-stage principal must remain trusted by deploy-customer-managed-policy."
    )


def test_validate_role_trust_excludes_apply_principal(resources):
    """validate-customer-managed-policy must NOT be assumable by the apply-stage principal."""
    arns = _principal_arns(resources["ValidateCustomerManagedPolicyRole"])
    for arn in arns:
        assert "-customer-managed-policies" not in arn, (
            "Apply principal must not be able to assume the read-only validate role."
        )


def test_validate_role_inline_policy_has_no_mutating_actions(resources):
    """Read-only role must grant only IAM read actions — no mutations ever."""
    role = resources["ValidateCustomerManagedPolicyRole"]
    statements = []
    for policy in role["Properties"]["Policies"]:
        statements.extend(policy["PolicyDocument"]["Statement"])
    forbidden = {
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:TagPolicy",
        "iam:UntagPolicy",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
    }
    for statement in statements:
        leaked = _actions(statement) & forbidden
        assert not leaked, (
            f"ValidateCustomerManagedPolicyRole grants mutating actions {leaked} "
            f"in statement Sid={statement.get('Sid')}; it must be read-only."
        )
