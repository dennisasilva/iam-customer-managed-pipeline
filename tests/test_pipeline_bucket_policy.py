# SPDX-License-Identifier: MIT
"""Structural tests for the artifact bucket policy in cfn/cx-mng-pipeline.yaml.

Asserts the state-integrity control (HIGH-2, lightweight variant): writes and
deletes on the ``state/`` prefix are denied to every principal except the
deploy CodeBuild role. This keeps drift-detection state trustworthy without
HMAC signing, because the set of writers is enforced by the bucket policy.
"""

from pathlib import Path

import pytest
import yaml


TEMPLATE = (
    Path(__file__).resolve().parent.parent / "cfn" / "cx-mng-pipeline.yaml"
)


class _CfnLoader(yaml.SafeLoader):
    """YAML loader that tolerates CloudFormation ``!Sub`` / ``!GetAtt`` tags."""


def _ignore_unknown(loader, tag_suffix, node):  # noqa: ANN001
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CfnLoader.add_multi_constructor("!", _ignore_unknown)


@pytest.fixture(scope="module")
def bucket_policy_statements() -> list:
    """Return the statements of the artifact bucket policy."""
    with open(TEMPLATE, "r", encoding="utf-8") as fh:
        doc = yaml.load(fh, Loader=_CfnLoader)
    policy = doc["Resources"]["CxMgrartifactsBucketPolicy"]
    return policy["Properties"]["PolicyDocument"]["Statement"]


def _actions(statement) -> set:
    action = statement.get("Action", [])
    return set(action if isinstance(action, list) else [action])


def _find_state_protection(statements):
    for s in statements:
        resource = s.get("Resource", "")
        resources = resource if isinstance(resource, list) else [resource]
        if any("/state/" in r for r in resources) and s.get("Effect") == "Deny":
            return s
    return None


def test_state_prefix_write_protection_exists(bucket_policy_statements):
    """A Deny statement must protect PutObject/DeleteObject on state/*."""
    stmt = _find_state_protection(bucket_policy_statements)
    assert stmt is not None, "No Deny statement protecting the state/ prefix found"
    assert {"s3:PutObject", "s3:DeleteObject"}.issubset(_actions(stmt)), (
        "state/ protection must deny both PutObject and DeleteObject"
    )


def test_state_protection_excepts_only_via_principal_arn(bucket_policy_statements):
    """The Deny must be gated by StringNotEquals on aws:PrincipalArn.

    That is the safe pattern: it denies everyone whose ARN is NOT the allowed
    writer, instead of the broader/riskier NotPrincipal construct.
    """
    stmt = _find_state_protection(bucket_policy_statements)
    assert stmt is not None
    condition = stmt.get("Condition", {})
    assert "StringNotEquals" in condition, (
        "state/ protection must use StringNotEquals (not NotPrincipal)"
    )
    assert "aws:PrincipalArn" in condition["StringNotEquals"], (
        "state/ protection must except the writer via aws:PrincipalArn"
    )


def test_state_protection_applies_to_all_principals(bucket_policy_statements):
    """Principal must be '*' so the Deny+condition covers every caller."""
    stmt = _find_state_protection(bucket_policy_statements)
    assert stmt is not None
    principal = stmt.get("Principal")
    assert principal == {"AWS": "*"} or principal == "*", (
        "state/ protection Deny must apply to all principals (Principal: '*')"
    )
