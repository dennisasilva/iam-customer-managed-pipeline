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

variable "organization_id" {
  description = <<-EOT
    AWS Organizations ID (e.g. "o-abcd1234") used to scope the pipeline's
    cross-account sts:AssumeRole permission via the aws:ResourceOrgID
    condition key. When set, both CodeBuild roles can only assume the
    deploy-customer-managed-policy role in accounts that are members of this
    organization, closing the ExternalId-leak path from a repo-only commit
    (CWE-272). Leave empty to preserve legacy behavior for existing
    deployments; combine with allowed_target_account_ids for defense in depth.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.organization_id == "" || can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id deve ser vazio ou corresponder a ^o-[a-z0-9]{10,32}$."
  }
}

variable "allowed_target_account_ids" {
  description = <<-EOT
    Lista explicita de contas AWS (IDs de 12 digitos) permitidas em qualquer
    array "Target" de templates/assignments/*.json. Injetada em todos os
    projetos CodeBuild como a variavel ALLOWED_TARGET_ACCOUNT_IDS; os scripts
    de validacao e deploy recusam sts:AssumeRole em contas fora da lista.
    O valor vive no stack da pipeline (configuracao confiavel) e NAO no
    repositorio alvo, portanto um commit nao consegue burlar o controle.
    Vazio desativa a checagem (nao recomendado; combine com organization_id).
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.allowed_target_account_ids : can(regex("^\\d{12}$", a))])
    error_message = "Cada entrada de allowed_target_account_ids deve ser exatamente 12 digitos."
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
