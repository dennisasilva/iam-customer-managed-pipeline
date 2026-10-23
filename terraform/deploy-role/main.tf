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
      # ExternalId como shared secret cross-account. O valor em CLARO precisa
      # ser literalmente embutido NESTA trust policy do IAM (nao ha como
      # referenciar um secret aqui), por isso ele e passado como variavel
      # 'sensitive' deste modulo. Na conta do PIPELINE, por outro lado, o
      # mesmo valor nao e passado como variavel nem embutido em nenhum
      # recurso: ele vive em um secret do Secrets Manager e e injetado nos
      # projetos CodeBuild via environment_variable { type = "SECRETS_MANAGER" },
      # de modo que codebuild:BatchGetProjects / BatchGetBuilds nao devolvem
      # o valor em claro. Rotacao: atualize PRIMEIRO o SecretString na conta
      # do pipeline (novos builds pegam o novo valor automaticamente), e so
      # ENTAO reaplique este modulo com o novo external_id em cada
      # conta-alvo. A ordem inversa bloqueia a pipeline.
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
