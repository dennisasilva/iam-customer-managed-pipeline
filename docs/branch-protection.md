# Branch Protection and Secure Release Workflow (deployment prerequisite)

This repository is the GitOps source for IAM customer-managed policy data
consumed by the pipeline defined in `cfn/cx-mng-pipeline.yaml` /
`terraform/`. The code the pipeline executes is **no longer taken from this
repository at pipeline runtime** - it is pinned via the `TrustedScripts*`
parameters (versioned S3 object + SHA-256 verified before execution).

To close the "arbitrary push triggers arbitrary code execution" path end to
end, the Git provider must enforce the following on the branch named by the
pipeline parameter `BranchName` (default: `main`). These settings live
outside IaC and MUST be configured as a deployment prerequisite:

## Required branch-protection settings

Configure on GitHub (Settings - Branches - Branch protection rule) or the
GitLab equivalent:

- Require a pull request before merging.
- Require approvals (minimum 1, 2 recommended) from reviewers listed in
  `CODEOWNERS`.
- Require review from Code Owners (CODEOWNERS enforcement enabled).
- Require signed commits (GPG / Sigstore / SSH key signatures).
- Require status checks to pass before merging.
- Require branches to be up to date before merging.
- Restrict who can push to matching branches - allow only release automation
  identities or named maintainers listed in `CODEOWNERS`.
- Do not allow force pushes, do not allow deletions.
- Enforce the rule for administrators (no bypass).

## Secure release workflow

1. Developer opens a PR against `main`. Reviewers verify both the data
   change (`templates/*.json`) and - if the PR touches `source/**/*.py`,
   `cfn/**`, `terraform/**`, `.github/**`, or `CODEOWNERS` - also run the
   security review path.
2. PR is merged after CODEOWNERS review of a signed commit.
3. If `source/**/*.py` changed, a release engineer:
   - Builds a reproducible `.tar.gz` from the merged commit SHA.
   - Uploads it to the write-restricted trusted-scripts bucket (ideally in
     a separate AWS account) under a new object version.
   - Captures the new S3 VersionId and `sha256sum` of the archive.
   - Updates the pipeline stack parameters (CFN) or Terraform variables:
     `TrustedScriptsKey`, `TrustedScriptsVersionId`, `TrustedScriptsSha256`
     and re-deploys the pipeline stack. Only this re-deploy makes the new
     scripts active.
4. The pipeline execution is started manually
   (`aws codepipeline start-pipeline-execution ...`). Auto-trigger is
   disabled (`DetectChanges=false`) so a push alone cannot start a run.

## Verification checklist (run after each pipeline-stack deployment)

- Source action: `DetectChanges` resolves to `false` on the deployed
  pipeline (`aws codepipeline get-pipeline` first stage action
  Configuration).
- Branch protection on `BranchName` enforces signed commits, CODEOWNERS,
  and no admin bypass.
- The three `TrustedScripts*` parameters are set to a specific
  object/version/SHA known to the operator; the bucket has
  Versioning + ideally Object Lock enabled.
- The buildspec is the stack-defined inline buildspec containing the
  `sha256sum` check and `aws s3api get-object --version-id` call (no
  inline `python3 source/...` without the trusted-scripts prelude).
