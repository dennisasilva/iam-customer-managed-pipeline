#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

"""Post-deploy smoke test for the iam-cx-mng-pipeline stack.

Run after ``aws cloudformation deploy`` to verify the stack is in a healthy
state and the resources the pipeline depends on are wired correctly. This
catches the class of failures that ``cfn-lint`` cannot:

  * Stack ended up in a failed state (drift between intended template and
    actual deploy result).
  * Expected IAM roles missing or drifted so their trust policy no longer
    names the expected service principal.
  * S3 artifact bucket not configured with the encryption we asked for, or
    missing the HTTPS-only / state/*-write Deny statements the bucket policy
    is required to carry.
  * CodeStar Connection in a state that will block the Source stage.
  * CodePipeline / CodeBuild projects missing, disabled, or drifted so the
    pipeline no longer carries the expected stages (including the Manual
    Approval gate when ``ManualApproval=true``).

The script is **read-only** — no AWS state is modified. Each check prints:
  * What it is checking (concrete resource and property)
  * Why the check matters (security or operational concern it covers)
  * What to do on failure (where to investigate)

Exit codes:
  0 - all checks passed
  1 - one or more checks failed (see logs for which)
  2 - script error (bad arguments, AWS credentials missing, etc.)

Usage:
  python3 scripts/post_deploy_smoke_test.py \\
      --stack-name cx-mng-policies-pipeline \\
      --naming-convention cx-mng-pipeline \\
      --region us-east-1
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


# Status considered acceptable for a successful deployment.
HEALTHY_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
}

# CodeStar Connection states that allow the pipeline to function.
HEALTHY_CONNECTION_STATUSES = {"AVAILABLE"}
# PENDING is the expected state right after stack creation, before the operator
# completes the OAuth handshake in the AWS console. We warn but do not fail.
WARN_CONNECTION_STATUSES = {"PENDING"}


# --------------------------------------------------------------------------- #
# Pretty-printing helpers
# --------------------------------------------------------------------------- #


@dataclass
class CheckResult:
    """Outcome of a single check, used for the final summary."""
    name: str
    passed: bool
    message: str = ""


def _print_banner(stack_name: str, region: str, naming: str, bucket_name: str) -> None:
    print("=" * 72)
    print("  Post-deploy smoke test for iam-cx-mng-pipeline")
    print(f"  Stack:              {stack_name} ({region})")
    print(f"  Naming convention:  {naming}")
    print(f"  Artifact bucket:    {bucket_name}")
    print("=" * 72)
    print()
    print("This script validates that a recently-deployed CloudFormation stack is")
    print("healthy and that the resources the pipeline depends on were created")
    print("correctly. It only READS — no AWS state is modified.")
    print()
    print("All checks below must pass for the pipeline to be operational. Each")
    print("check prints what it is testing, why it matters, and where to look on")
    print("failure.")
    print()


def _print_section(num: str, title: str) -> None:
    print()
    print("-" * 72)
    print(f"[{num}] {title}")
    print("-" * 72)


def _print_check_intro(checking: str, why: str, on_failure: str) -> None:
    print()
    print(f"  ▸ Checking : {checking}")
    print(f"    Why      : {why}")
    print(f"    Failure  : {on_failure}")


def _run_check(label: str, fn: Callable[[], bool], results: list) -> None:
    """Run ``fn``, log PASS/FAIL, and append a CheckResult."""
    try:
        passed = fn()
        marker = "✅ PASS" if passed else "❌ FAIL"
        print(f"    Result   : {marker} - {label}")
        results.append(CheckResult(name=label, passed=passed))
    except (ClientError, BotoCoreError) as exc:
        print(f"    Result   : ❌ FAIL - {label}")
        print(f"               {exc}")
        results.append(CheckResult(name=label, passed=False, message=str(exc)))


def parse_args() -> argparse.Namespace:
    """Parse and return the command-line arguments."""
    parser = argparse.ArgumentParser(description="Post-deploy smoke test")
    parser.add_argument(
        "--stack-name",
        required=True,
        help="CloudFormation stack name to verify.",
    )
    parser.add_argument(
        "--naming-convention",
        required=True,
        help="Value passed as NamingConvention parameter to the stack.",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region the stack was deployed to. Default: us-east-1",
    )
    return parser.parse_args()


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #


def check_stack_status(cfn, stack_name: str) -> bool:
    """Stack must be in a healthy CREATE/UPDATE_COMPLETE-like state."""
    response = cfn.describe_stacks(StackName=stack_name)
    stacks = response.get("Stacks", [])
    if not stacks:
        print(f"               Stack {stack_name!r} not found")
        return False
    status = stacks[0]["StackStatus"]
    print(f"               Reported status: {status}")
    return status in HEALTHY_STACK_STATUSES


def _trust_policy_services(trust_doc) -> set:
    """Return the set of Service principals from an AssumeRolePolicyDocument."""
    services: set = set()
    if not isinstance(trust_doc, dict):
        return services
    for stmt in trust_doc.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "sts:AssumeRole" not in actions:
            continue
        principal = stmt.get("Principal", {})
        if not isinstance(principal, dict):
            continue
        svc = principal.get("Service", [])
        if isinstance(svc, str):
            services.add(svc)
        else:
            services.update(svc or [])
    return services


def check_iam_role_exists(iam, role_name: str, expected_service: str = "codebuild.amazonaws.com") -> bool:
    """The role must exist and trust the expected AWS service principal.

    Verifying the AssumeRolePolicyDocument closes a false-green where the role
    exists but has been drifted to trust an unexpected principal (or no
    principal), which would silently neutralize the pipeline's identity model.
    """
    response = iam.get_role(RoleName=role_name)
    trust_doc = response.get("Role", {}).get("AssumeRolePolicyDocument", {})
    services = _trust_policy_services(trust_doc)
    print(f"               Trusted service principals: {sorted(services) or '(none)'}")
    if expected_service not in services:
        print(
            f"               Expected trust for {expected_service!r} not found. "
            "Trust policy drift detected."
        )
        return False
    return True


def check_codepipeline_exists(
    codepipeline, name: str, require_approval: Optional[bool] = None
) -> bool:
    """Pipeline must exist, carry the expected stages, and honor the Approval gate.

    When ``require_approval`` is True, the pipeline must contain an Approval
    stage with a Manual approval action — the only human gate between a Git
    commit and ``sts:AssumeRole`` + ``iam:CreatePolicy`` in every target
    account. When False, we accept its absence (deliberately configured off).
    When None, the stage check is skipped.
    """
    response = codepipeline.get_pipeline(name=name)
    pipeline = response.get("pipeline", {})
    stages = pipeline.get("stages", []) or []
    stage_names = [s.get("name") for s in stages]
    print(f"               Pipeline stages: {stage_names}")

    # The non-conditional stages that must always be present.
    required_stages = {
        "Source",
        "TemplateValidation",
        "RoleValidation",
        "DryRun",
        "CustomerManagedPolicies",
    }
    missing = required_stages - set(stage_names)
    if missing:
        print(f"               Missing required stages: {sorted(missing)}")
        return False

    def _has_manual_approval(stage) -> bool:
        if stage.get("name") != "Approval":
            return False
        for action in stage.get("actions", []) or []:
            type_id = action.get("actionTypeId", {}) or {}
            if (
                type_id.get("category") == "Approval"
                and type_id.get("provider") == "Manual"
            ):
                return True
        return False

    approval_present = any(_has_manual_approval(s) for s in stages)
    if require_approval is True and not approval_present:
        print(
            "               Manual approval stage missing. The stack was "
            "deployed with ManualApproval=true but no Approval/Manual action "
            "is present on the pipeline (possible out-of-band update-pipeline "
            "drift)."
        )
        return False
    if require_approval is False and approval_present:
        print(
            "               Unexpected Manual Approval stage. Stack was "
            "deployed with ManualApproval=false but the pipeline carries one."
        )
        # Not a hard failure: an operator explicitly adding a human gate is
        # strictly safer than the configured posture, so we warn but pass.
    return True


def check_codebuild_project_exists(codebuild, name: str) -> bool:
    response = codebuild.batch_get_projects(names=[name])
    return bool(response.get("projects"))


def _bucket_policy_statements(s3, bucket_name: str) -> list:
    """Return the parsed statement list of the bucket policy, or []"""
    response = s3.get_bucket_policy(Bucket=bucket_name)
    doc = json.loads(response["Policy"])
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return statements


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def check_artifact_bucket_https_only(s3, bucket_name: str) -> bool:
    """Bucket policy must deny all requests over plain HTTP (aws:SecureTransport).

    This is the ``HTTPSOnly`` Deny statement declared by
    ``cfn/cx-mng-pipeline.yaml`` on the artifact bucket. Losing it (console/CLI
    delete-bucket-policy, or CFN drift) silently removes the TLS requirement
    from the pipeline's artifact and state storage.
    """
    statements = _bucket_policy_statements(s3, bucket_name)
    for s in statements:
        if s.get("Effect") != "Deny":
            continue
        actions = set(_as_list(s.get("Action")))
        if "s3:*" not in actions and not any(a == "s3:*" for a in actions):
            # Only s3:* (or an explicit superset) qualifies as a global HTTPS
            # gate. A narrower Action would leave other calls unprotected.
            continue
        condition = s.get("Condition", {}) or {}
        bool_cond = condition.get("Bool", {}) or {}
        secure_transport = bool_cond.get("aws:SecureTransport")
        if isinstance(secure_transport, list):
            secure_transport = secure_transport[0] if secure_transport else None
        if str(secure_transport).lower() == "false":
            return True
    print(
        "               HTTPSOnly Deny (aws:SecureTransport=false) not found "
        "in bucket policy."
    )
    return False


def check_artifact_bucket_state_write_protection(
    s3, bucket_name: str, deploy_role_arn: Optional[str]
) -> bool:
    """Bucket policy must deny PutObject/DeleteObject on state/* to every
    principal except the deploy CodeBuild role.

    This is the ``RestrictStateWritesToDeployRole`` Deny: it is what makes the
    drift-detection state in ``state/<account>.json`` trustworthy without
    HMAC signing. Losing it would allow any principal in the account to tamper
    with the state files that drive the deploy script's skip/visit decisions.
    """
    statements = _bucket_policy_statements(s3, bucket_name)
    for s in statements:
        if s.get("Effect") != "Deny":
            continue
        actions = set(_as_list(s.get("Action")))
        if not {"s3:PutObject", "s3:DeleteObject"}.issubset(actions):
            continue
        resources = _as_list(s.get("Resource"))
        if not any("/state/" in r for r in resources):
            continue
        condition = s.get("Condition", {}) or {}
        sne = condition.get("StringNotEquals", {}) or {}
        allowed_arn = sne.get("aws:PrincipalArn")
        if isinstance(allowed_arn, list):
            allowed_arn = allowed_arn[0] if allowed_arn else None
        if not allowed_arn:
            print(
                "               state/ Deny found but it does not except "
                "a specific aws:PrincipalArn via StringNotEquals."
            )
            return False
        if deploy_role_arn and allowed_arn != deploy_role_arn:
            print(
                f"               state/ Deny excepts {allowed_arn!r} but the "
                f"deploy CodeBuild role is {deploy_role_arn!r}."
            )
            return False
        print(f"               state/ writes restricted to: {allowed_arn}")
        return True
    print(
        "               No Deny on PutObject/DeleteObject for state/* found "
        "in bucket policy."
    )
    return False


def check_artifact_bucket_encryption(s3, bucket_name: str) -> bool:
    """Bucket must be encrypted with SSE-KMS (any KMS key)."""
    response = s3.get_bucket_encryption(Bucket=bucket_name)
    rules = response["ServerSideEncryptionConfiguration"]["Rules"]
    if not rules:
        return False
    algorithm = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    print(f"               Encryption algorithm: {algorithm}")
    return algorithm == "aws:kms"


def check_artifact_bucket_public_access_blocked(s3, bucket_name: str) -> bool:
    """All four BlockPublicAccess flags must be true."""
    response = s3.get_public_access_block(Bucket=bucket_name)
    config = response["PublicAccessBlockConfiguration"]
    expected = ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"]
    return all(config.get(k) is True for k in expected)


def check_artifact_bucket_versioning(s3, bucket_name: str) -> bool:
    """Bucket versioning must be Enabled (state files depend on it)."""
    response = s3.get_bucket_versioning(Bucket=bucket_name)
    return response.get("Status") == "Enabled"


def check_codestar_connection(codeconnections, naming_filter: str) -> bool:
    """A CodeStar Connection should exist matching the stack's naming."""
    response = codeconnections.list_connections()
    connections = response.get("Connections", [])
    matching = [c for c in connections if naming_filter in c.get("ConnectionName", "")]
    if not matching:
        print(f"               No CodeStar Connection matching {naming_filter!r}")
        return False
    for conn in matching:
        status = conn["ConnectionStatus"]
        print(f"               Connection {conn['ConnectionName']}: {status}")
        if status in HEALTHY_CONNECTION_STATUSES:
            return True
        if status in WARN_CONNECTION_STATUSES:
            print(
                "               WARNING: connection is PENDING — operator must "
                "complete the OAuth handshake in the AWS console before the "
                "Source stage can run."
            )
            return True  # PENDING is expected immediately after first deploy
    return False


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def main() -> int:  # noqa: PLR0915 - one-shot script with linear setup
    """Run every check, log results, return an aggregate exit code."""
    args = parse_args()

    region = args.region
    naming = args.naming_convention
    stack = args.stack_name

    cfn = boto3.client("cloudformation", region_name=region)
    iam = boto3.client("iam", region_name=region)
    codepipeline = boto3.client("codepipeline", region_name=region)
    codebuild = boto3.client("codebuild", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    codeconnections = boto3.client("codeconnections", region_name=region)
    sts = boto3.client("sts", region_name=region)

    try:
        account_id = sts.get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as exc:
        print(f"FATAL: Could not determine account ID: {exc}", file=sys.stderr)
        print("       Check that AWS credentials are configured (aws configure / SSO).", file=sys.stderr)
        return 2

    bucket_name = f"{account_id}-{region}-cx-mng-artfcs"

    # Resolve stack parameters we need for posture assertions. In particular
    # ManualApproval decides whether we insist on the Approval stage.
    manual_approval_expected: Optional[bool] = None
    try:
        stack_desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        for p in stack_desc.get("Parameters", []) or []:
            if p.get("ParameterKey") == "ManualApproval":
                manual_approval_expected = str(p.get("ParameterValue", "")).lower() == "true"
                break
    except (ClientError, BotoCoreError, KeyError, IndexError):
        # describe_stacks fail is already covered by the stack-health check
        # below; here we just leave manual_approval_expected as None so the
        # pipeline-stage assertion is permissive rather than wrongly failing.
        manual_approval_expected = None

    deploy_role_name = f"{naming}-customer-managed-policies"
    deploy_role_arn = f"arn:aws:iam::{account_id}:role/{deploy_role_name}"

    _print_banner(stack, region, naming, bucket_name)

    results: list[CheckResult] = []

    # ------------------------------------------------------------ #
    # 1. Stack health
    # ------------------------------------------------------------ #
    _print_section("1/13", "CloudFormation stack health")
    _print_check_intro(
        checking=f"Stack {stack!r} reports a healthy *_COMPLETE status",
        why=(
            "A stack in ROLLBACK_FAILED or UPDATE_ROLLBACK_FAILED means "
            "CloudFormation couldn't apply the template. Resources are in an "
            "inconsistent state and the pipeline cannot run."
        ),
        on_failure=(
            "AWS Console > CloudFormation > <stack> > Events tab. "
            "The first ERROR row shows the root cause."
        ),
    )
    _run_check(
        f"Stack '{stack}' is in a healthy state",
        lambda: check_stack_status(cfn, stack),
        results,
    )

    # ------------------------------------------------------------ #
    # 2-5. IAM roles
    # ------------------------------------------------------------ #
    _print_section("2-5/13", "IAM roles")
    _print_check_intro(
        checking=f"4 IAM roles named '{naming}-*' exist",
        why=(
            "Each stage needs its dedicated role: role-validation calls "
            "sts:AssumeRole on target accounts, template-validation reads "
            "policy JSONs, customer-managed-policies executes the deploy "
            "(create/update/delete IAM policies via assumed cross-account "
            "credentials), and code-pipeline orchestrates the whole pipeline."
        ),
        on_failure=(
            "Likely a NamingConvention parameter mismatch or a CFN deploy "
            "that didn't reach the Resources section. Re-check the deploy "
            "command and the stack Events tab."
        ),
    )
    expected_roles = [
        (f"{naming}-role-validation", "codebuild.amazonaws.com"),
        (f"{naming}-template-validation", "codebuild.amazonaws.com"),
        (f"{naming}-customer-managed-policies", "codebuild.amazonaws.com"),
        (f"{naming}-code-pipeline", "codepipeline.amazonaws.com"),
    ]
    for role, expected_service in expected_roles:
        _run_check(
            f"IAM role exists and trusts {expected_service}: {role}",
            lambda r=role, svc=expected_service: check_iam_role_exists(iam, r, svc),
            results,
        )

    # ------------------------------------------------------------ #
    # 6. CodePipeline
    # ------------------------------------------------------------ #
    _print_section("6/13", "CodePipeline")
    pipeline_name = f"{naming}-pipeline"
    _print_check_intro(
        checking=f"CodePipeline '{pipeline_name}' exists",
        why=(
            "Without the CodePipeline, GitHub pushes don't trigger any "
            "validation or deploy. The whole solution depends on this single "
            "resource being present."
        ),
        on_failure=(
            "Check the AWS::CodePipeline::Pipeline resource in cx-mng-pipeline.yaml "
            "and the stack Events tab for creation errors."
        ),
    )
    _run_check(
        f"CodePipeline exists with expected stages: {pipeline_name}",
        lambda: check_codepipeline_exists(
            codepipeline, pipeline_name, require_approval=manual_approval_expected
        ),
        results,
    )

    # ------------------------------------------------------------ #
    # 7-10. CodeBuild projects
    # ------------------------------------------------------------ #
    _print_section("7-10/13", "CodeBuild projects")
    _print_check_intro(
        checking="4 CodeBuild projects exist (one per pipeline build stage)",
        why=(
            "Each pipeline stage that runs Python (TemplateValidation, "
            "RoleValidation, DryRun, CustomerManagedPolicies) is implemented "
            "as a CodeBuild project. A missing project means that stage fails "
            "with a 'project not found' error."
        ),
        on_failure=(
            "Check that all 4 AWS::CodeBuild::Project resources exist in "
            "cx-mng-pipeline.yaml under the expected NamingConvention prefix."
        ),
    )
    expected_projects = [
        f"{naming}-template-validation",
        f"{naming}-role-validation",
        f"{naming}-dry-run",
        f"{naming}-customer-managed-policies",
    ]
    for project in expected_projects:
        _run_check(
            f"CodeBuild project exists: {project}",
            lambda p=project: check_codebuild_project_exists(codebuild, p),
            results,
        )

    # ------------------------------------------------------------ #
    # 11. S3 artifact bucket — encryption
    # ------------------------------------------------------------ #
    _print_section("11/13", "S3 artifact bucket — encryption")
    _print_check_intro(
        checking=f"Bucket '{bucket_name}' is encrypted with SSE-KMS",
        why=(
            "Pipeline state files (state/<account>.json) live here. KMS "
            "encryption (vs. plain AES256) lets us audit usage in CloudTrail "
            "and enforce KMS-via-S3 conditions on the IAM roles."
        ),
        on_failure=(
            "Check BucketEncryption in cx-mng-pipeline.yaml. The expected "
            "value is SSEAlgorithm: 'aws:kms'."
        ),
    )
    _run_check(
        f"Bucket has SSE-KMS encryption: {bucket_name}",
        lambda: check_artifact_bucket_encryption(s3, bucket_name),
        results,
    )

    # ------------------------------------------------------------ #
    # 12. S3 artifact bucket — public access blocked
    # ------------------------------------------------------------ #
    _print_section("12/13", "S3 artifact bucket — public access blocked")
    _print_check_intro(
        checking=f"Bucket '{bucket_name}' has all 4 BlockPublicAccess flags true",
        why=(
            "Pipeline artifacts and state files must never be exposed publicly. "
            "All 4 flags (BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, "
            "RestrictPublicBuckets) defend against ACL-based and bucket-policy-"
            "based public exposure."
        ),
        on_failure=(
            "Check PublicAccessBlockConfiguration in cx-mng-pipeline.yaml. "
            "All 4 flags must be true."
        ),
    )
    _run_check(
        "Bucket BlockPublicAccess is fully enabled",
        lambda: check_artifact_bucket_public_access_blocked(s3, bucket_name),
        results,
    )

    # ------------------------------------------------------------ #
    # 13. S3 artifact bucket — versioning enabled
    # ------------------------------------------------------------ #
    _print_section("13/13", "S3 artifact bucket — versioning enabled")
    _print_check_intro(
        checking=f"Bucket '{bucket_name}' has versioning enabled",
        why=(
            "Versioning protects state files against accidental deletion or "
            "malicious tampering. It is also a prerequisite for the "
            "NoncurrentVersionExpiration lifecycle rule the bucket uses."
        ),
        on_failure=(
            "Check VersioningConfiguration: Status: Enabled in cx-mng-pipeline.yaml."
        ),
    )
    _run_check(
        "Bucket versioning is Enabled",
        lambda: check_artifact_bucket_versioning(s3, bucket_name),
        results,
    )

    # ------------------------------------------------------------ #
    # Bucket policy — HTTPS-only Deny
    # ------------------------------------------------------------ #
    _print_section("policy-1", "S3 artifact bucket — HTTPS-only Deny")
    _print_check_intro(
        checking=(
            f"Bucket '{bucket_name}' policy denies requests with "
            "aws:SecureTransport=false"
        ),
        why=(
            "The HTTPSOnly Deny in the template is what forces TLS on every "
            "artifact and state read/write. Losing it (delete-bucket-policy, "
            "console edit, CFN drift) silently permits cleartext S3 access to "
            "the pipeline's state files."
        ),
        on_failure=(
            "Re-apply cfn/cx-mng-pipeline.yaml so the bucket policy is "
            "restored, or inspect `aws s3api get-bucket-policy` to see the "
            "current statements."
        ),
    )
    _run_check(
        "Bucket policy denies non-TLS requests (HTTPSOnly)",
        lambda: check_artifact_bucket_https_only(s3, bucket_name),
        results,
    )

    # ------------------------------------------------------------ #
    # Bucket policy — state/* write protection
    # ------------------------------------------------------------ #
    _print_section(
        "policy-2", "S3 artifact bucket — state/* write protection"
    )
    _print_check_intro(
        checking=(
            f"Bucket '{bucket_name}' policy denies PutObject/DeleteObject on "
            f"state/* to every principal except {deploy_role_arn}"
        ),
        why=(
            "The state/<account>.json objects decide whether a policy update "
            "is skipped and which accounts are visited for deletion. The "
            "RestrictStateWritesToDeployRole Deny is what makes drift state "
            "trustworthy without HMAC signing: only the deploy CodeBuild role "
            "is allowed to write it. Losing this Deny lets any principal in "
            "the account tamper with the state and steer the deploy script."
        ),
        on_failure=(
            "Re-apply cfn/cx-mng-pipeline.yaml so the RestrictStateWrites "
            "ToDeployRole Deny is restored, and confirm the deploy role ARN "
            "in the StringNotEquals condition matches the current stack."
        ),
    )
    _run_check(
        "Bucket policy restricts state/ writes to the deploy CodeBuild role",
        lambda: check_artifact_bucket_state_write_protection(
            s3, bucket_name, deploy_role_arn
        ),
        results,
    )

    # ------------------------------------------------------------ #
    # 14. CodeStar Connection (informational — listed last because PENDING is OK)
    # ------------------------------------------------------------ #
    _print_section("info", "CodeStar Connection")
    _print_check_intro(
        checking=f"A CodeStar Connection matching '{stack}' exists",
        why=(
            "The Source stage uses this connection to pull from GitHub. "
            "PENDING right after first deploy is normal — the operator must "
            "complete the OAuth handshake in the AWS console before the "
            "pipeline can run."
        ),
        on_failure=(
            "AWS Console > Developer Tools > Settings > Connections. "
            "Click on the connection and complete the GitHub OAuth flow."
        ),
    )
    _run_check(
        "CodeStar Connection in AVAILABLE or PENDING state",
        lambda: check_codestar_connection(codeconnections, stack),
        results,
    )

    # ------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------ #
    print()
    print("=" * 72)
    print("  Summary")
    print("=" * 72)
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    if failed > 0:
        print(f"  {failed}/{total} checks FAILED:")
        for r in results:
            if not r.passed:
                print(f"     ❌ {r.name}")
                if r.message:
                    print(f"        {r.message}")
        print()
        print("  Smoke test FAILED — review the [Failure] hints above before")
        print("  trying to use the pipeline.")
        return 1

    print(f"  {passed}/{total} checks passed.")
    print()
    print("  Smoke test PASSED — the stack is operationally healthy.")
    print()
    print("  Next steps:")
    print("    * If the CodeStar Connection is PENDING, complete the OAuth")
    print("      handshake in the AWS console before pushing to GitHub.")
    print("    * Push a commit to the configured branch (BranchName parameter)")
    print("      to trigger the first pipeline run end-to-end.")
    print("    * Watch the CodePipeline console for stage progression.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
