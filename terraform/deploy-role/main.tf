# SPDX-License-Identifier: MIT
# Equivalente Terraform, POR CONTA, de cfn/cx-mng-stackset-deploy-role.yaml.
#
# Observação importante sobre multi-conta:
#   O template CFN é implantado via StackSet (SERVICE_MANAGED) e cria a role
#   em TODAS as contas de uma OU automaticamente. Terraform não tem StackSet;
#   aplique este módulo UMA VEZ POR CONTA-ALVO (com o provider apontando para
#   a conta correta, via credenciais/assume-role). Para org inteira, o
#   StackSet do CloudFormation continua sendo o caminho mais simples.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "Região AWS (a role IAM é global, mas o provider exige região)."
  type        = string
  default     = "us-east-1"
}

variable "pipeline_account_id" {
  description = "ID (12 dígitos) da conta que hospeda a pipeline."
  type        = string
  validation {
    condition     = can(regex("^\\d{12}$", var.pipeline_account_id))
    error_message = "pipeline_account_id deve ter exatamente 12 dígitos."
  }
}

variable "naming_convention" {
  description = "Deve ser igual ao naming_convention da pipeline."
  type        = string
  default     = "cx-mng-pipeline"
}

variable "external_id" {
  description = "Shared secret. Deve ser IGUAL ao external_id da pipeline. Gere via 'openssl rand -hex 32'."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{16,64}$", var.external_id))
    error_message = "external_id deve ter 16-64 caracteres: alfanuméricos, hífen ou underscore."
  }
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Read-only role used by the pre-approval RoleValidation and DryRun stages.
# Separating this from the mutation-capable deploy role is a CWE-653
# compartmentalization control: a tampered pre-approval script can obtain at
# most these IAM read actions and cannot create/modify/delete any IAM policy.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "validate" {
  name        = "validate-customer-managed-policy"
  description = "Read-only role assumed by the pipeline pre-approval validation and dry-run stages to inspect IAM customer-managed policies in this account."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        # Only the two pre-approval CodeBuild service roles may assume this
        # read-only role; the apply-stage principal is intentionally excluded.
        AWS = [
          "arn:aws:iam::${var.pipeline_account_id}:role/${var.naming_convention}-role-validation",
          "arn:aws:iam::${var.pipeline_account_id}:role/${var.naming_convention}-dry-run",
        ]
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = { "sts:ExternalId" = var.external_id }
      }
    }]
  })

  tags = {
    "cx-mng"    = "true"
    "ManagedBy" = "sso-pipeline"
  }
}

resource "aws_iam_role_policy" "validate" {
  name = "customer-managed-policy-validate"
  role = aws_iam_role.validate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMPolicyReadOnly"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicies",
          "iam:ListPolicyTags",
          "iam:ListPolicyVersions",
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/deploy-customer-managed-policy",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/validate-customer-managed-policy",
        ]
      },
    ]
  })
}

output "validate_role_arn" {
  description = "ARN da role de validação (read-only) criada nesta conta."
  value       = aws_iam_role.validate.arn
}

# ---------------------------------------------------------------------------
# Mutation-capable role used ONLY by the post-approval apply stage.
# RoleValidation and DryRun principals are intentionally NOT trusted here.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "deploy" {
  name        = "deploy-customer-managed-policy"
  description = "Role assumed by the pipeline to manage IAM customer-managed policies in this account."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = [
          # Only the apply-stage CodeBuild service role may assume this
          # mutation-capable role.
          "arn:aws:iam::${var.pipeline_account_id}:role/${var.naming_convention}-customer-managed-policies",
        ]
      }
      Action = "sts:AssumeRole"
      # ExternalId como shared secret: mesmo que a conta do pipeline seja
      # comprometida, quem tiver só o ARN da role não a assume sem o ExternalId.
      Condition = {
        StringEquals = { "sts:ExternalId" = var.external_id }
      }
    }]
  })

  tags = {
    "cx-mng"    = "true"
    "ManagedBy" = "sso-pipeline"
  }
}

resource "aws_iam_role_policy" "deploy" {
  name = "customer-managed-policy-management"
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Leitura + criação. CreatePolicy não pode ser restrito por tag porque
      # a policy (e a tag) ainda não existem no momento da criação; o script
      # aplica cx-mng:true logo em seguida via TagPolicy.
      {
        Sid    = "IAMPolicyReadAndCreate"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:ListPolicies",
          "iam:ListPolicyVersions",
          "iam:ListPolicyTags",
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/deploy-customer-managed-policy",
        ]
      },
      # Ações destrutivas/mutantes só em policies que já têm cx-mng:true.
      # Faz do IAM (não só do script) o ponto de enforcement.
      {
        Sid    = "IAMPolicyModifyOnlyTagged"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:DeletePolicy",
          "iam:DeletePolicyVersion",
          "iam:TagPolicy",
          "iam:UntagPolicy",
        ]
        Resource  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*"
        Condition = { StringEquals = { "aws:ResourceTag/cx-mng" = "true" } }
      },
    ]
  })
}

output "deploy_role_arn" {
  description = "ARN da role de deploy criada nesta conta."
  value       = aws_iam_role.deploy.arn
}
