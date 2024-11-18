resource "aws_codepipeline" "pipeline" {
  name     = "cx-mng-policies-pipeline"
  role_arn = aws_iam_role.pipeline_role.arn

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
        ConnectionArn  = aws_codestarconnections_connection.github.arn
        FullRepositoryId = "${var.repository_owner}/${var.repository_name}"
        BranchName       = "main"
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
