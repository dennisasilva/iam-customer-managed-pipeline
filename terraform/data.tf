# SPDX-License-Identifier: MIT
# Data sources e valores derivados.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Mesmo padrão de nome do CFN: ${AccountId}-${Region}-cx-mng-artfcs
  artifact_bucket_name = "${local.account_id}-${local.region}-cx-mng-artfcs"

  # ARN da role cross-account de deploy (criada nas contas-alvo).
  deploy_role_arn = "arn:aws:iam::*:role/deploy-customer-managed-policy"

  # ARN do segredo em Secrets Manager que guarda o shared secret ExternalId.
  # Aceita um nome simples OU um ARN completo em var.external_id_secret_id.
  # Para nomes, construímos o padrão ARN com sufixo "-*" (os 6 chars aleatórios
  # que o Secrets Manager anexa). Isso mantém a permissão escopada a um único
  # segredo em qualquer um dos casos.
  external_id_secret_arn = startswith(var.external_id_secret_id, "arn:") ? var.external_id_secret_id : "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.external_id_secret_id}-*"

  # Seleciona a conexão CodeStar de acordo com o tipo de repositório.
  is_github      = var.repository_type == "GitHub"
  connection_arn = local.is_github ? aws_codestarconnections_connection.github[0].arn : aws_codestarconnections_connection.gitlab[0].arn
}
