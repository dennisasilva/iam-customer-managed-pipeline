# SPDX-License-Identifier: MIT
# Data sources e valores derivados.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Mesmo padrão de nome do CFN: ${AccountId}-${Region}-cx-mng-artfcs
  artifact_bucket_name = "${local.account_id}-${local.region}-cx-mng-artfcs"

  # ARN da role cross-account de deploy (criada nas contas-alvo). O wildcard
  # na parte da conta é mantido para permitir que a lista de contas gerenciadas
  # seja alterada via var.allowed_account_ids sem reescrever o Resource; a
  # fronteira de contenção real é aplicada pela Condition
  # aws:ResourceAccount / aws:ResourceOrgID (ver local.cross_account_assume_condition
  # em iam.tf).
  deploy_role_arn = "arn:aws:iam::*:role/deploy-customer-managed-policy"

  # Seleciona a conexão CodeStar de acordo com o tipo de repositório.
  is_github      = var.repository_type == "GitHub"
  connection_arn = local.is_github ? aws_codestarconnections_connection.github[0].arn : aws_codestarconnections_connection.gitlab[0].arn
}
