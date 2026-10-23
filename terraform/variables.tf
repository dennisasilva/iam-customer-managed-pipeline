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

variable "external_id_secret_arn" {
  description = "ARN completo de um secret do AWS Secrets Manager cujo SecretString e o ExternalId usado em todo sts:AssumeRole cross-account. O valor DEVE ser identico ao external_id da role de deploy nas contas-alvo. Crie o secret separadamente (aws secretsmanager create-secret --name ... --secret-string <openssl rand -hex 32>) ANTES do apply. O valor em claro NUNCA entra em variavel Terraform nem no state: cada CodeBuild project recebe apenas a referencia via environment_variable { type = \"SECRETS_MANAGER\" }, e as roles de build ganham secretsmanager:GetSecretValue + kms:Decrypt apenas neste secret."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:\\d{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.external_id_secret_arn))
    error_message = "external_id_secret_arn deve ser o ARN completo de um secret do Secrets Manager."
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
