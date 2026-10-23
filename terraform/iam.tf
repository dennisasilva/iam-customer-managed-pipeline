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
        # Leitura do SourceOutput + listagem.
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"]
        Resource = [local.bucket_arn, "${local.bucket_arn}/*"]
      },
      {
        # Escrita escopada ao proprio prefixo de saida deste estagio.
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:AbortMultipartUpload"]
        Resource = [
          "${local.bucket_arn}/${var.naming_convention}-pipeline/TemplateValidationOutput/*",
        ]
      },
      {
        # Download do bundle imutavel de scripts (SHA-256 verificado).
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = [
          "arn:aws:s3:::${var.trusted_scripts_bucket}/${var.trusted_scripts_key}",
        ]
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
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"]
        Resource = [local.bucket_arn, "${local.bucket_arn}/*"]
      },
      {
        # Escrita escopada ao proprio prefixo de saida deste estagio.
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:AbortMultipartUpload"]
        Resource = [
          "${local.bucket_arn}/${var.naming_convention}-pipeline/RoleValidationOutput/*",
        ]
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = [
          "arn:aws:s3:::${var.trusted_scripts_bucket}/${var.trusted_scripts_key}",
        ]
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
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"]
        Resource = [local.bucket_arn, "${local.bucket_arn}/*"]
      },
      {
        # Apply + dry-run compartilham a role, cada um escreve apenas no seu
        # proprio prefixo de saida (nao pode reescrever SourceOutput nem o
        # artefato de outro estagio).
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:AbortMultipartUpload"]
        Resource = [
          "${local.bucket_arn}/${var.naming_convention}-pipeline/CustomerManagedPoliciesOutput/*",
          "${local.bucket_arn}/${var.naming_convention}-pipeline/DryRunOutput/*",
        ]
      },
      {
        # Drift state writes/deletes (ainda limitado por bucket policy).
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:DeleteObject"]
        Resource = ["${local.bucket_arn}/state/*"]
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = [
          "arn:aws:s3:::${var.trusted_scripts_bucket}/${var.trusted_scripts_key}",
        ]
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
