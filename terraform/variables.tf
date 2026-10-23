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
  description = "Shared secret usado em todo sts:AssumeRole cross-account. Deve ser IGUAL ao ExternalId da role de deploy nas contas-alvo. Gere via 'openssl rand -hex 32'. DEPRECATED: prefira external_id_secret_arn para evitar exposição como env var em texto puro."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{16,64}$", var.external_id))
    error_message = "external_id deve ter 16-64 caracteres: alfanuméricos, hífen ou underscore."
  }
}

variable "external_id_secret_arn" {
  description = "ARN opcional de um secret do Secrets Manager contendo o ExternalId. Quando preenchido, os projetos CodeBuild recebem EXTERNAL_ID com type=SECRETS_MANAGER (nunca aparece em texto puro na definição do projeto). Vazio = cai no var.external_id acima."
  type        = string
  default     = ""
  sensitive   = true

  validation {
    condition     = var.external_id_secret_arn == "" || can(regex("^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.external_id_secret_arn))
    error_message = "external_id_secret_arn deve ser vazio ou um ARN válido de Secrets Manager."
  }
}

variable "organization_id" {
  description = "ID da AWS Organizations (o-xxxxxxxxxx). Quando preenchido, as políticas IAM dos CodeBuild restringem sts:AssumeRole a roles dentro desta organização (aws:ResourceOrgID), substituindo o wildcard arn:aws:iam::*:role/..."
  type        = string
  default     = ""

  validation {
    condition     = var.organization_id == "" || can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id deve ser vazio ou corresponder a o-[a-z0-9]{10,32}."
  }
}

variable "allowed_account_ids" {
  description = "Lista de IDs de conta AWS (12 dígitos) que podem ser alvo de assignments. Entregue às builds via a variável de ambiente ALLOWED_ACCOUNT_IDS (defesa em profundidade contra CWE-639: aim de mutações IAM cross-account para contas arbitrárias). Vazio = usar organizations:ListAccounts via allowed_account_ids_resolver."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.allowed_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "Cada entrada de allowed_account_ids deve ter exatamente 12 dígitos."
  }
}

variable "allowed_account_ids_resolver" {
  description = "Como resolver o allowlist. 'static' usa var.allowed_account_ids. 'organizations' chama organizations:ListAccounts no runtime (requer organizations:ListAccounts na role da pipeline)."
  type        = string
  default     = "static"

  validation {
    condition     = contains(["static", "organizations"], var.allowed_account_ids_resolver)
    error_message = "allowed_account_ids_resolver deve ser 'static' ou 'organizations'."
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
