# SPDX-License-Identifier: MIT
# CodePipeline V2 — paridade com o CodePipeline do CFN.
# Estágios: Source -> TemplateValidation -> [Approval (opcional)] ->
#           RoleValidation -> DryRun -> CustomerManagedPolicies
# A aprovação manual é colocada ANTES de qualquer estágio com credenciais
# cross-account para que código advindo do repositório nunca execute com
# credenciais privilegiadas sem revisão humana.

resource "aws_codepipeline" "pipeline" {
  name          = "${var.naming_convention}-pipeline"
  role_arn      = aws_iam_role.code_pipeline.arn
  pipeline_type = "V2"

  artifact_store {
    location = aws_s3_bucket.artifacts.id
    type     = "S3"
  }

  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["SourceOutput"]
      configuration = {
        ConnectionArn    = local.connection_arn
        FullRepositoryId = "${var.repository_owner}/${var.repository_name}"
        BranchName       = var.branch_name
        DetectChanges    = "true"
      }
    }
  }

  stage {
    name = "TemplateValidation"
    action {
      name             = "TemplateValidation"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceOutput"]
      output_artifacts = ["TemplateValidationOutput"]
      configuration = {
        ProjectName = aws_codebuild_project.template_validation.name
      }
    }
  }

  # Estágio de aprovação manual — posicionado ANTES de qualquer estágio que
  # carregue credenciais cross-account (RoleValidation/DryRun assumem a role
  # de leitura; CustomerManagedPolicies assume a de escrita). Humano revisa o
  # commit antes de qualquer AssumeRole em contas-alvo, eliminando o caminho
  # de execução de código pré-aprovação com credenciais privilegiadas.
  dynamic "stage" {
    for_each = var.manual_approval ? [1] : []
    content {
      name = "Approval"
      action {
        name     = "Approval"
        category = "Approval"
        owner    = "AWS"
        provider = "Manual"
        version  = "1"
        configuration = {
          CustomData = "Review the commit (templates + source scripts) before any stage runs with cross-account credentials."
        }
      }
    }
  }

  stage {
    name = "RoleValidation"
    action {
      name             = "RoleValidation"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceOutput"]
      output_artifacts = ["RoleValidationOutput"]
      configuration = {
        ProjectName = aws_codebuild_project.role_validation.name
      }
    }
  }

  stage {
    name = "DryRun"
    action {
      name             = "DryRun"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceOutput"]
      output_artifacts = ["DryRunOutput"]
      configuration = {
        ProjectName = aws_codebuild_project.dry_run.name
      }
    }
  }

  stage {
    name = "CustomerManagedPolicies"
    action {
      name             = "CustomerManagedPolicies"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceOutput"]
      output_artifacts = ["CustomerManagedPoliciesOutput"]
      configuration = {
        ProjectName = aws_codebuild_project.customer_managed_policies.name
      }
    }
  }
}
