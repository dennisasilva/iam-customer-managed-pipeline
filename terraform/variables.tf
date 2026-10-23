# SPDX-License-Identifier: MIT
# Variáveis de entrada — espelham os Parameters de cfn/cx-mng-pipeline.yaml.

variable "region" {
  description = "Região AWS onde a pipeline será criada."
  type        = string
  default     = "us-east-1"
}

variable "repository_type" {
  description = "Tipo do repositório para a conexão CodeStar (GitHub ou GitLab)."
  type        = string
  default     = "GitHub"

  validation {
    condition     = contains(["GitHub", "GitLab"], var.repository_type)
    error_message = "repository_type deve ser 'GitHub' ou 'GitLab'."
  }
}

variable "repository_name" {
  description = "Nome do repositório de origem."
  type        = string
  default     = "iam-cx-mng-pipeline"
}

variable "repository_owner" {
  description = "Owner (usuário/org) do repositório de origem."
  type        = string
  default     = "dennisasilva"
}

variable "branch_name" {
  description = "Branch rastreada pela pipeline."
  type        = string
  default     = "main"
}

variable "external_id" {
  description = "Shared secret usado em todo sts:AssumeRole cross-account. Deve ser IGUAL ao ExternalId da role de deploy nas contas-alvo. Gere via 'openssl rand -hex 32'."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{16,64}$", var.external_id))
    error_message = "external_id deve ter 16-64 caracteres: alfanuméricos, hífen ou underscore."
  }
}

variable "naming_convention" {
  description = "Prefixo dos nomes de recursos/roles. Limitado a 30 chars (mantém RoleName IAM <= 64)."
  type        = string
  default     = "cx-mng-pipeline"

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]*[a-z0-9])?$", var.naming_convention)) && length(var.naming_convention) <= 30
    error_message = "naming_convention deve ser lowercase, começar com letra, terminar com letra/número, apenas letras/números/hífens, até 30 chars."
  }
}

variable "manual_approval" {
  description = "Habilita o estágio de aprovação manual antes do deploy das policies."
  type        = bool
  default     = true
}

variable "allowed_target_account_ids" {
  description = <<-EOT
    Lista autoritativa de AWS account IDs (12 dígitos) em que a pipeline tem
    permissão de deploy. Injetada como variável de ambiente ALLOWED_TARGET_ACCOUNT_IDS
    nos projetos CodeBuild e usada para:
      (1) rejeitar entradas Target que não estejam nesta lista nos scripts de
          validation/deploy; e
      (2) restringir sts:AssumeRole dos CodeBuild roles ao conjunto exato de
          ARNs 'arn:aws:iam::<id>:role/deploy-customer-managed-policy'
          (em vez do curinga 'arn:aws:iam::*:...').
    Deve ser mantida FORA do repositório GitOps (atualizada só via Terraform/
    pipeline infra), de modo que um commit no repo-alvo não possa expandir o
    conjunto de contas que a pipeline pode acessar.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for a in var.allowed_target_account_ids : can(regex("^[0-9]{12}$", a))
    ])
    error_message = "Cada entrada em allowed_target_account_ids deve ser um AWS account ID de 12 dígitos."
  }
}

# ---------------------------------------------------------------------------
# Observação de escopo (paridade com o CloudFormation):
#
# O template CFN também cria um recurso AWS::CodeStar::GitHubRepository, que
# faz o *bootstrap* do repositório GitHub a partir de um .zip no S3, e usa um
# SecretId (Secrets Manager) como token. Esse recurso é específico do
# CloudFormation e NÃO tem equivalente direto no Terraform. Portanto, esta
# variante assume que o repositório JÁ existe e apenas conecta a pipeline a
# ele via CodeStar Connection. Por isso não há variáveis para
# S3BucketCodeBucket / S3BucketCodeKey / SecretId aqui.
# ---------------------------------------------------------------------------
