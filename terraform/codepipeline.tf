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

  # Estágio de aprovação manual — agora SEMPRE presente (CWE-841).
  # A variável manual_approval é mantida apenas por compatibilidade e sua
  # validação rejeita o valor false. O ExternalEntityLink aponta para os
  # logs do CodeBuild DryRun (código confiável), não para texto do commit.
  # A permissão codepipeline:PutApprovalResult desta action está restrita à
  # role aws_iam_role.approver (ver iam.tf) e explicitamente negada aos
  # principals em source_push_principal_arns via
  # aws_iam_policy.deny_self_approval.
  stage {
    name = "Approval"
    action {
      name     = "Approval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"
      configuration = merge(
        {
          CustomData         = "Review the DryRun build logs linked in ExternalEntityLink (produced by the trusted DryRun CodeBuild project) before approving. Approver MUST NOT be the same identity that pushed the commit."
          ExternalEntityLink = "https://${var.region}.console.aws.amazon.com/codesuite/codebuild/projects/${aws_codebuild_project.dry_run.name}/history?region=${var.region}"
        },
        var.approval_notification_arn == "" ? {} : { NotificationArn = var.approval_notification_arn },
      )
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
