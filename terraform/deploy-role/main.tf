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

resource "aws_iam_role" "deploy" {
  name        = "deploy-customer-managed-policy"
  description = "Role assumed by the pipeline to manage IAM customer-managed policies in this account."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = [
          "arn:aws:iam::${var.pipeline_account_id}:role/${var.naming_convention}-role-validation",
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
          "iam:UntagPolicy",
        ]
        Resource  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*"
        Condition = { StringEquals = { "aws:ResourceTag/cx-mng" = "true" } }
      },
      # TagPolicy exige, além da tag atual, que a request não reescreva
      # cx-mng para algo diferente de 'true'. Assim, mesmo que o script
      # repasse Tags vindas do repositório, o IAM bloqueia a sobrescrita
      # da tag de propriedade antes que a policy fique órfã.
      # StringEqualsIfExists permite TagPolicy sem incluir cx-mng.
      {
        Sid    = "IAMTagPolicyPreserveOwnership"
        Effect = "Allow"
        Action = "iam:TagPolicy"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*"
        Condition = {
          StringEquals         = { "aws:ResourceTag/cx-mng" = "true" }
          StringEqualsIfExists = { "aws:RequestTag/cx-mng" = "true" }
        }
      },
      # Deny explícito: nenhuma UntagPolicy desta role pode remover a tag
      # cx-mng. Deny tem precedente sobre Allow, então o IAM bloqueia
      # qualquer tentativa de "opt-out" via remoção da tag de propriedade.
      {
        Sid    = "DenyUntagOwnership"
        Effect = "Deny"
        Action = "iam:UntagPolicy"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*"
        Condition = {
          "ForAnyValue:StringEquals" = {
            "aws:TagKeys" = ["cx-mng"]
          }
        }
      },
    ]
  })
}

output "deploy_role_arn" {
  description = "ARN da role de deploy criada nesta conta."
  value       = aws_iam_role.deploy.arn
}
