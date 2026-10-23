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

variable "external_id_secret_id" {
  description = <<-EOT
    Nome (ou ARN) do segredo em AWS Secrets Manager que armazena o shared
    secret ExternalId usado nos sts:AssumeRole cross-account. O VALOR do
    segredo (não este nome) deve ser IGUAL ao ExternalId da role de deploy
    nas contas-alvo. O CodeBuild resolve o valor em tempo de build via uma
    environment_variable do tipo SECRETS_MANAGER, de forma que o plaintext
    nunca entra na definição do projeto nem no estado do Terraform.
    Gere o valor armazenado via 'openssl rand -hex 32'.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9/_+=.@-]+$", var.external_id_secret_id)) && length(var.external_id_secret_id) >= 1 && length(var.external_id_secret_id) <= 512
    error_message = "external_id_secret_id deve conter apenas letras, números e os caracteres / _ + = . @ -, com 1 a 512 chars."
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
