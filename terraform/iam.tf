# SPDX-License-Identifier: MIT
# Roles IAM da pipeline (paridade com os 4 roles do CFN).
# Padrão comum: logs*, S3 escopado ao bucket de artefatos e KMS restrito a
# chamadas feitas pelo S3 desta região (kms:ViaService).

locals {
  codebuild_assume = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  bucket_arn = aws_s3_bucket.artifacts.arn

  logs_statement = {
    Effect   = "Allow"
    Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    Resource = "*"
  }

  kms_via_s3_statement = {
    Effect   = "Allow"
    Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
    Resource = "*"
    Condition = {
      StringEquals = { "kms:ViaService" = "s3.${local.region}.amazonaws.com" }
    }
  }
}

# ---------- Template Validation ----------
resource "aws_iam_role" "template_validation" {
  name               = "${var.naming_convention}-template-validation"
  description        = "CodeBuild role for Template Validation CodeBuild Project"
  path               = "/"
  assume_role_policy = local.codebuild_assume
}

resource "aws_iam_role_policy" "template_validation" {
  name = "CodeBuildPolicy"
  role = aws_iam_role.template_validation.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.logs_statement,
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:AbortMultipartUpload"]
        Resource = [local.bucket_arn, "${local.bucket_arn}/*"]
      },
      local.kms_via_s3_statement,
    ]
  })
}

# ---------- Role Validation ----------
resource "aws_iam_role" "role_validation" {
  name               = "${var.naming_convention}-role-validation"
  description        = "CodeBuild role for Role Validation CodeBuild Project"
  path               = "/"
  assume_role_policy = local.codebuild_assume
}

resource "aws_iam_role_policy" "role_validation" {
  name = "CodeBuildPolicy"
  role = aws_iam_role.role_validation.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.logs_statement,
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [local.bucket_arn, "${local.bucket_arn}/*"]
      },
      local.kms_via_s3_statement,
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = local.deploy_role_arn
      },
    ]
  })
}

# ---------- Customer Managed Policies (deploy + dry-run) ----------
resource "aws_iam_role" "customer_managed_policies" {
  name               = "${var.naming_convention}-customer-managed-policies"
  description        = "CodeBuild role for Customer Managed Policies CodeBuild Project"
  path               = "/"
  assume_role_policy = local.codebuild_assume
}

resource "aws_iam_role_policy" "customer_managed_policies" {
  name = "CodeBuildPolicy"
  role = aws_iam_role.customer_managed_policies.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.logs_statement,
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [local.bucket_arn, "${local.bucket_arn}/*"]
      },
      local.kms_via_s3_statement,
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = local.deploy_role_arn
      },
    ]
  })
}

# ---------- CodePipeline ----------
resource "aws_iam_role" "code_pipeline" {
  name        = "${var.naming_convention}-code-pipeline"
  description = "CodePipeline role for the CI/CD pipeline"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codepipeline.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "code_pipeline" {
  name = "CodePipelinePolicy"
  role = aws_iam_role.code_pipeline.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["codebuild:StartBuild", "codebuild:BatchGetBuilds", "codebuild:StopBuild"]
        Resource = "*"
      },
      local.logs_statement,
      {
        Effect   = "Allow"
        Action   = ["codestar-connections:UseConnection", "codestar-connections:PassConnection"]
        Resource = local.connection_arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketPolicy",
          "s3:GetObject",
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
        ]
        Resource  = ["${local.bucket_arn}*", "${local.bucket_arn}/*"]
        Condition = { StringEquals = { "s3:ResourceAccount" = local.account_id } }
      },
      local.kms_via_s3_statement,
    ]
  })
}

# ---------- Approver role (separation of duties, CWE-841) ----------
# Role assumed by human approvers to call codepipeline:PutApprovalResult on
# this pipeline's Approval action. Trust is restricted to the principals in
# var.approver_principal_arns and additionally requires MFA on the caller.
# Only created when the operator supplies approvers; if the list is empty,
# the Approval stage is still mandatory and the operator provisions the
# permission out of band.
locals {
  pipeline_arn          = "arn:${data.aws_partition.current.partition}:codepipeline:${local.region}:${local.account_id}:${aws_codepipeline.pipeline.name}"
  approval_action_arn   = "${local.pipeline_arn}/Approval/Approval"
  create_approver_role  = length(var.approver_principal_arns) > 0
}

resource "aws_iam_role" "approver" {
  count       = local.create_approver_role ? 1 : 0
  name        = "${var.naming_convention}-approver"
  description = "Role that human approvers assume to approve the pipeline Approval action (separation of duties)."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.approver_principal_arns }
      Action    = "sts:AssumeRole"
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "approver" {
  count = local.create_approver_role ? 1 : 0
  name  = "ApprovePipelineAction"
  role  = aws_iam_role.approver[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ApprovePipelineAction"
      Effect = "Allow"
      Action = [
        "codepipeline:PutApprovalResult",
        "codepipeline:GetPipelineState",
        "codepipeline:GetPipelineExecution",
      ]
      Resource = [
        local.approval_action_arn,
        local.pipeline_arn,
      ]
    }]
  })
}

# ---------- Deny-self-approval managed policy ----------
# Managed deny policy an operator attaches to every principal that can push
# to the tracked source branch. The attachment itself is intentionally left
# to the operator (Terraform must not own pre-existing identities): the
# policy ARN is exposed via outputs.tf so it can be referenced by other
# modules or by `aws iam attach-role-policy`.
resource "aws_iam_policy" "deny_self_approval" {
  name        = "${var.naming_convention}-deny-self-approval"
  description = "Deny codepipeline:PutApprovalResult on this pipeline's Approval action. Attach to every principal that can push to the source branch."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DenySelfApproval"
      Effect   = "Deny"
      Action   = ["codepipeline:PutApprovalResult"]
      Resource = [local.approval_action_arn]
    }]
  })
}
