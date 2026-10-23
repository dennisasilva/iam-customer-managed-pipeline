#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

"""Post-deploy smoke test for the iam-cx-mng-pipeline stack.

Run after ``aws cloudformation deploy`` to verify the stack is in a healthy
state and the resources the pipeline depends on are wired correctly. This
catches the class of failures that ``cfn-lint`` cannot:

  * Stack ended up in a failed state (drift between intended template and
    actual deploy result).
  * Expected IAM roles missing (race condition or naming-convention drift).
  * S3 artifact bucket not configured with the encryption we asked for.
  * CodeStar Connection in a state that will block the Source stage.
  * CodePipeline / CodeBuild projects missing or disabled.

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
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Union

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
# completes the OAuth handshake in the AWS console. We warn but do not count
# PENDING as a passing check — the Source stage cannot run until the operator
# completes the handshake, so the aggregate verdict must not report the stack
# as fully healthy.
WARN_CONNECTION_STATUSES = {"PENDING"}

# Logical IDs of the CodeStar Connection resources in cfn/cx-mng-pipeline.yaml.
# One of these is created depending on the RepositoryType parameter.
CODESTAR_CONNECTION_LOGICAL_IDS = (
    "CodeStarConnectionGitHub",
    "CodeStarConnectionGitLab",
)


class CheckOutcome(Enum):
    """Tri-state result for an individual check.

    ``PASS``  — the check succeeded.
    ``WARN``  — the check surfaced a non-fatal operational issue the operator
                 must address (e.g. a CodeStar Connection waiting for the
                 OAuth handshake). It is NOT counted toward the aggregate
                 "all checks passed / stack is operationally healthy" verdict.
    ``FAIL``  — the check failed.
    """

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


# --------------------------------------------------------------------------- #
# Pretty-printing helpers
# --------------------------------------------------------------------------- #


@dataclass
class CheckResult:
    """Outcome of a single check, used for the final summary."""
    name: str
    outcome: CheckOutcome
    message: str = ""

    @property
    def passed(self) -> bool:
        """Backward-compatible: True only for a strict PASS (not WARN)."""
        return self.outcome is CheckOutcome.PASS

    @property
    def warned(self) -> bool:
        return self.outcome is CheckOutcome.WARN


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


def _run_check(
    label: str,
    fn: Callable[[], Union[bool, CheckOutcome]],
    results: list,
) -> None:
    """Run ``fn``, log PASS/WARN/FAIL, and append a CheckResult.

    ``fn`` may return either a bool (legacy two-state check) or a
    :class:`CheckOutcome` (tri-state check).
    """
    try:
        raw = fn()
        if isinstance(raw, CheckOutcome):
            outcome = raw
        else:
            outcome = CheckOutcome.PASS if raw else CheckOutcome.FAIL
        marker = {
            CheckOutcome.PASS: "✅ PASS",
            CheckOutcome.WARN: "⚠️  WARN",
            CheckOutcome.FAIL: "❌ FAIL",
        }[outcome]
        print(f"    Result   : {marker} - {label}")
        results.append(CheckResult(name=label, outcome=outcome))
    except (ClientError, BotoCoreError) as exc:
        print(f"    Result   : ❌ FAIL - {label}")
        print(f"               {exc}")
        results.append(
            CheckResult(name=label, outcome=CheckOutcome.FAIL, message=str(exc))
        )


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


def check_iam_role_exists(iam, role_name: str) -> bool:
    iam.get_role(RoleName=role_name)
    return True


def check_codepipeline_exists(codepipeline, name: str) -> bool:
    codepipeline.get_pipeline(name=name)
    return True


def check_codebuild_project_exists(codebuild, name: str) -> bool:
    response = codebuild.batch_get_projects(names=[name])
    return bool(response.get("projects"))


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


def _resolve_stack_connection_arn(cfn, codepipeline, stack_name: str) -> str:
    """Return the ConnectionArn the stack actually uses.

    Preference order:

    1. The physical resource id of ``CodeStarConnectionGitHub`` or
       ``CodeStarConnectionGitLab`` on the stack (one of them exists depending
       on the RepositoryType parameter — see cfn/cx-mng-pipeline.yaml).
    2. Falling back to the ``ConnectionArn`` configured on the pipeline's
       Source action (cfn/cx-mng-pipeline.yaml:742).

    Raises :class:`LookupError` if neither resolution path finds a connection.
    """
    paginator = cfn.get_paginator("describe_stack_resources")
    # describe_stack_resources is not paginated server-side, but using the
    # paginator keeps the code uniform and future-proof.
    seen_logical_ids: list[str] = []
    try:
        pages = paginator.paginate(StackName=stack_name)
    except (ClientError, BotoCoreError):
        pages = [cfn.describe_stack_resources(StackName=stack_name)]
    for page in pages:
        for resource in page.get("StackResources", []):
            logical_id = resource.get("LogicalResourceId", "")
            seen_logical_ids.append(logical_id)
            if (
                logical_id in CODESTAR_CONNECTION_LOGICAL_IDS
                and resource.get("ResourceType")
                == "AWS::CodeStarConnections::Connection"
            ):
                arn = resource.get("PhysicalResourceId")
                if arn:
                    return arn

    # Fallback: read the pipeline's Source action ConnectionArn configuration.
    pipeline_name = f"{stack_name}-pipeline"
    try:
        pipeline = codepipeline.get_pipeline(name=pipeline_name)["pipeline"]
    except (ClientError, BotoCoreError) as exc:
        raise LookupError(
            f"Could not resolve CodeStar ConnectionArn: stack {stack_name!r} "
            f"has no {CODESTAR_CONNECTION_LOGICAL_IDS} resource and the "
            f"pipeline lookup failed: {exc}"
        ) from exc
    for stage in pipeline.get("stages", []):
        for action in stage.get("actions", []):
            config = action.get("configuration", {}) or {}
            arn = config.get("ConnectionArn")
            if arn:
                return arn
    raise LookupError(
        f"Could not resolve CodeStar ConnectionArn for stack {stack_name!r}: "
        f"neither {CODESTAR_CONNECTION_LOGICAL_IDS} resource found on the "
        f"stack nor a ConnectionArn in pipeline {pipeline_name!r}."
    )


def check_codestar_connection(
    codeconnections,
    naming_filter: str,
    *,
    cfn=None,
    codepipeline=None,
) -> CheckOutcome:
    """Check the CodeStar Connection the stack actually created.

    Resolves the exact ConnectionArn from the stack's ``CodeStarConnection*``
    resource (or, as a fallback, from the pipeline's Source action) and calls
    ``get_connection`` on that ARN. Only ``AVAILABLE`` is reported as a PASS;
    ``PENDING`` is a non-fatal WARN that is excluded from the aggregate
    "stack is operationally healthy" verdict (operator must complete the
    OAuth handshake). Any other status (``ERROR`` and the like) is a FAIL.

    ``naming_filter`` is the stack name — kept for backwards compatibility
    with the previous signature and used to resolve the stack's resources.
    ``cfn`` and ``codepipeline`` are keyword-only clients used for ARN
    resolution; when omitted, they default to boto3 clients in the current
    session/region so that direct callers still work.
    """
    if cfn is None:
        cfn = boto3.client("cloudformation")
    if codepipeline is None:
        codepipeline = boto3.client("codepipeline")

    try:
        connection_arn = _resolve_stack_connection_arn(
            cfn, codepipeline, naming_filter
        )
    except LookupError as exc:
        print(f"               {exc}")
        return CheckOutcome.FAIL

    response = codeconnections.get_connection(ConnectionArn=connection_arn)
    conn = response.get("Connection", {})
    name = conn.get("ConnectionName", connection_arn)
    status = conn.get("ConnectionStatus", "UNKNOWN")
    print(f"               Connection {name} ({connection_arn}): {status}")

    if status in HEALTHY_CONNECTION_STATUSES:
        return CheckOutcome.PASS
    if status in WARN_CONNECTION_STATUSES:
        print(
            "               WARNING: connection is PENDING — operator must "
            "complete the OAuth handshake in the AWS console before the "
            "Source stage can run. This check is reported as WARN and is "
            "excluded from the 'all checks passed' verdict."
        )
        return CheckOutcome.WARN
    print(
        f"               Connection status {status!r} is neither AVAILABLE "
        f"nor PENDING — the Source stage cannot run."
    )
    return CheckOutcome.FAIL


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
        f"{naming}-role-validation",
        f"{naming}-template-validation",
        f"{naming}-customer-managed-policies",
        f"{naming}-code-pipeline",
    ]
    for role in expected_roles:
        _run_check(
            f"IAM role exists: {role}",
            lambda r=role: check_iam_role_exists(iam, r),
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
        f"CodePipeline exists: {pipeline_name}",
        lambda: check_codepipeline_exists(codepipeline, pipeline_name),
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
    # 14. CodeStar Connection (reported last; PENDING is a non-fatal WARN)
    # ------------------------------------------------------------ #
    _print_section("info", "CodeStar Connection")
    _print_check_intro(
        checking=f"A CodeStar Connection matching '{stack}' exists",
        why=(
            "The Source stage uses this connection to pull from GitHub. "
            "PENDING right after first deploy is expected but means the "
            "OAuth handshake is incomplete and the Source stage cannot run; "
            "it is reported as WARN and excluded from the aggregate 'stack "
            "is operationally healthy' verdict until the operator completes "
            "the handshake in the AWS console."
        ),
        on_failure=(
            "AWS Console > Developer Tools > Settings > Connections. "
            "Click on the connection and complete the GitHub OAuth flow."
        ),
    )
    _run_check(
        "CodeStar Connection in AVAILABLE state (PENDING → WARN)",
        lambda: check_codestar_connection(
            codeconnections, stack, cfn=cfn, codepipeline=codepipeline
        ),
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
    passed = sum(1 for r in results if r.outcome is CheckOutcome.PASS)
    warned = sum(1 for r in results if r.outcome is CheckOutcome.WARN)
    failed = sum(1 for r in results if r.outcome is CheckOutcome.FAIL)

    if failed > 0:
        print(f"  {failed}/{total} checks FAILED:")
        for r in results:
            if r.outcome is CheckOutcome.FAIL:
                print(f"     ❌ {r.name}")
                if r.message:
                    print(f"        {r.message}")
        if warned > 0:
            print(f"  {warned}/{total} checks reported WARN:")
            for r in results:
                if r.outcome is CheckOutcome.WARN:
                    print(f"     ⚠️  {r.name}")
        print()
        print("  Smoke test FAILED — review the [Failure] hints above before")
        print("  trying to use the pipeline.")
        return 1

    if warned > 0:
        print(f"  {passed}/{total} checks passed, {warned}/{total} WARN:")
        for r in results:
            if r.outcome is CheckOutcome.WARN:
                print(f"     ⚠️  {r.name}")
        print()
        print("  Smoke test completed with WARNINGS — the stack is NOT yet")
        print("  fully operational. Address every WARN above (typically:")
        print("  complete the CodeStar Connection OAuth handshake in the AWS")
        print("  console) and re-run this script before using the pipeline.")
        return 1

    print(f"  {passed}/{total} checks passed.")
    print()
    print("  Smoke test PASSED — the stack is operationally healthy.")
    print()
    print("  Next steps:")
    print("    * Push a commit to the configured branch (BranchName parameter)")
    print("      to trigger the first pipeline run end-to-end.")
    print("    * Watch the CodePipeline console for stage progression.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
