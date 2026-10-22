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
  # O account field é um wildcard porque a role existe em cada conta gerenciada
  # (criada pelo StackSet). O acesso é restringido pela condition
  # aws:ResourceOrgID = var.org_id aplicada em todo sts:AssumeRole (veja
  # local.assume_deploy_role_statement em iam.tf), para que uma conta fora da
  # Organization não possa ser assumida mesmo que um Target de 12 dígitos
  # qualquer apareça em templates/assignments/*.json.
  deploy_role_arn = "arn:aws:iam::*:role/deploy-customer-managed-policy"

  # Seleciona a conexão CodeStar de acordo com o tipo de repositório.
  is_github      = var.repository_type == "GitHub"
  connection_arn = local.is_github ? aws_codestarconnections_connection.github[0].arn : aws_codestarconnections_connection.gitlab[0].arn
}
