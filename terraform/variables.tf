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
  description = "Mantida por compatibilidade. O estágio de aprovação manual é OBRIGATÓRIO (CWE-841) e não pode ser desativado. Only `true` is accepted."
  type        = bool
  default     = true

  validation {
    condition     = var.manual_approval == true
    error_message = "manual_approval cannot be disabled: the human gate before cross-account IAM deployment is mandatory."
  }
}

variable "approver_principal_arns" {
  description = "Lista de ARNs de IAM principals autorizados a aprovar o estágio Approval. São o único grupo com permissão codepipeline:PutApprovalResult sobre esta pipeline (separation of duties). Deixe vazio para somente criar o deny policy e provisionar o acesso de aprovação fora deste módulo."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.approver_principal_arns : can(regex("^arn:aws[a-zA-Z-]*:iam::\\d{12}:(role|user|root)(/.*)?$", arn))])
    error_message = "approver_principal_arns deve conter ARNs IAM válidos (role, user ou root)."
  }
}

variable "source_push_principal_arns" {
  description = "Lista informativa de IAM principals que podem fazer push na branch rastreada. O módulo não anexa políticas a esses principals (Terraform não deve possuir identidades pré-existentes), mas cria um managed deny policy que o operador DEVE anexar a cada um deles para impedir self-approval."
  type        = list(string)
  default     = []
}

variable "approval_notification_arn" {
  description = "ARN do tópico SNS que recebe notificações de Approval. Quando definido, o Approval action publica a notificação out-of-band com o ExternalEntityLink para os logs do DryRun. Deixe vazio para desabilitar."
  type        = string
  default     = ""

  validation {
    condition     = var.approval_notification_arn == "" || can(regex("^arn:aws[a-zA-Z-]*:sns:[a-z0-9-]+:\\d{12}:[A-Za-z0-9_-]+$", var.approval_notification_arn))
    error_message = "approval_notification_arn deve ser vazio ou um ARN SNS válido."
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
