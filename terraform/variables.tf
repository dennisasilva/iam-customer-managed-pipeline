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

# ---------------------------------------------------------------------------
# Scripts confiáveis (write-restricted + imutáveis). O buildspec baixa este
# objeto S3 pinando pela version-id, verifica SHA-256 e só então executa
# qualquer Python. Nenhum arquivo de source/ no SourceOutput da branch
# rastreada é executado.
# ---------------------------------------------------------------------------
variable "trusted_scripts_bucket" {
  description = "Bucket S3 (write-restricted) que hospeda o bundle imutável de scripts (.tar.gz)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.trusted_scripts_bucket))
    error_message = "trusted_scripts_bucket deve ser um nome válido de bucket S3 (3-63 chars, lowercase)."
  }
}

variable "trusted_scripts_key" {
  description = "Chave S3 do bundle de scripts (.tar.gz / .tgz) dentro de trusted_scripts_bucket."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9._/-]+\\.(tar\\.gz|tgz)$", var.trusted_scripts_key))
    error_message = "trusted_scripts_key deve terminar em .tar.gz ou .tgz."
  }
}

variable "trusted_scripts_version_id" {
  description = "Version-id S3 do objeto trusted_scripts_key. Pinar a version-id torna o download reprodutível mesmo se o objeto for sobrescrito."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.trusted_scripts_version_id))
    error_message = "trusted_scripts_version_id deve conter apenas letras, números, pontos, underscores e hífens."
  }
}

variable "trusted_scripts_sha256" {
  description = "SHA-256 (64 hex chars minúsculos) do bundle apontado por trusted_scripts_key@trusted_scripts_version_id. Comparado byte-a-byte no buildspec antes de executar qualquer script."
  type        = string

  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.trusted_scripts_sha256))
    error_message = "trusted_scripts_sha256 deve ser exatamente 64 caracteres hexadecimais em minúsculo."
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
