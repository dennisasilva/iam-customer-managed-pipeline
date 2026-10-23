# SPDX-License-Identifier: MIT
# CodePipeline V2 — paridade com o CodePipeline do CFN.
# Estágios: Source -> TemplateValidation -> RoleValidation -> DryRun ->
#           [Approval (opcional)] -> CustomerManagedPolicies

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

  # Estágio de aprovação manual — agora OBRIGATÓRIO. Os estágios RoleValidation
  # e DryRun que rodam antes dele executam Python controlado pelo repositório;
  # um humano precisa gatilhar toda mudança em produção (CWE-653 /
  # separação de funções). A variável ``manual_approval`` foi mantida para
  # compatibilidade de inputs, mas está obsoleta e é ignorada.
  stage {
    name = "Approval"
    action {
      name     = "Approval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"
      configuration = {
        CustomData = "Review DryRun logs and approve before deploying customer managed policies."
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
