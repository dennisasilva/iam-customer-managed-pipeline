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
  # Se allowed_target_account_ids for fornecida, restringimos a lista ao
  # conjunto exato de ARNs para que, mesmo se a validação aplicacional for
  # contornada, um sts:AssumeRole em uma conta fora da lista seja negado
  # pelo IAM. Caso contrário mantemos o curinga para compatibilidade com
  # instalações existentes (hardening gap documentado).
  deploy_role_arns = length(var.allowed_target_account_ids) > 0 ? [
    for a in var.allowed_target_account_ids :
    "arn:aws:iam::${a}:role/deploy-customer-managed-policy"
  ] : ["arn:aws:iam::*:role/deploy-customer-managed-policy"]

  # Mantemos o atributo singular por compatibilidade com código que ainda o
  # referencie; aponta para o primeiro elemento quando ele já é uma lista.
  deploy_role_arn = local.deploy_role_arns[0]

  # Valor serializado passado para o CodeBuild como ALLOWED_TARGET_ACCOUNT_IDS.
  # String vazia quando a variável não foi configurada (os scripts emitem um
  # warning nesse caso em vez de falhar, preservando compatibilidade).
  allowed_target_account_ids_env = join(",", var.allowed_target_account_ids)

  # Seleciona a conexão CodeStar de acordo com o tipo de repositório.
  is_github      = var.repository_type == "GitHub"
  connection_arn = local.is_github ? aws_codestarconnections_connection.github[0].arn : aws_codestarconnections_connection.gitlab[0].arn
}
