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
  # Mantém o wildcard no segmento de conta (necessário porque o conjunto
  # exato de contas-alvo não é estático no template), mas o acesso é agora
  # restringido pela condition aws:ResourceOrgID em iam.tf quando
  # var.organization_id é definido, impedindo que uma mudança no
  # repositório direcione o sts:AssumeRole para uma conta fora da
  # AWS Organization (CWE-272).
  deploy_role_arn = "arn:aws:iam::*:role/deploy-customer-managed-policy"

  # Condition inserida nas policy statements de sts:AssumeRole quando
  # organization_id for fornecido. Vazia caso contrário (backward compat).
  deploy_role_assume_condition = var.organization_id == "" ? {} : {
    Condition = {
      StringEquals = { "aws:ResourceOrgID" = var.organization_id }
    }
  }

  # String CSV com a allow-list para o CodeBuild env var
  # ALLOWED_TARGET_ACCOUNT_IDS. Vazia desativa a checagem nos scripts.
  allowed_target_account_ids_csv = join(",", var.allowed_target_account_ids)

  # Seleciona a conexão CodeStar de acordo com o tipo de repositório.
  is_github      = var.repository_type == "GitHub"
  connection_arn = local.is_github ? aws_codestarconnections_connection.github[0].arn : aws_codestarconnections_connection.gitlab[0].arn
}
