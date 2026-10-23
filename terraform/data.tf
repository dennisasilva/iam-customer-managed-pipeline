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
  # Mantido como wildcard por conveniência IAM, mas combinado com uma Condition
  # aws:ResourceOrgID (quando var.organization_id está preenchido) para
  # restringir sts:AssumeRole a roles DENTRO da organização governada.
  # Veja local.assume_role_statement abaixo.
  deploy_role_arn = "arn:aws:iam::*:role/deploy-customer-managed-policy"

  # Statement reutilizável de sts:AssumeRole para as roles de CodeBuild
  # customer_managed_policies e role_validation. Quando organization_id está
  # vazio, cai de volta para o antigo wildcard; quando preenchido, adiciona
  # aws:ResourceOrgID (substitui o wildcard pela organização governada —
  # mitigação CWE-639: deploy não pode mirar contas arbitrárias no mundo).
  assume_role_statement = merge(
    {
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = "arn:aws:iam::*:role/deploy-customer-managed-policy"
    },
    var.organization_id == "" ? {} : {
      Condition = {
        StringEquals = { "aws:ResourceOrgID" = var.organization_id }
      }
    }
  )

  # Seleciona a conexão CodeStar de acordo com o tipo de repositório.
  is_github      = var.repository_type == "GitHub"
  connection_arn = local.is_github ? aws_codestarconnections_connection.github[0].arn : aws_codestarconnections_connection.gitlab[0].arn
}
