# SPDX-License-Identifier: MIT
# Outputs úteis pós-apply.

output "pipeline_name" {
  description = "Nome do CodePipeline criado."
  value       = aws_codepipeline.pipeline.name
}

output "artifact_bucket" {
  description = "Bucket S3 de artefatos e state."
  value       = aws_s3_bucket.artifacts.id
}

output "codestar_connection_arn" {
  description = "ARN da conexão CodeStar. Conclua o handshake no console (status PENDING -> AVAILABLE)."
  value       = local.connection_arn
}

output "codebuild_projects" {
  description = "Nomes dos projetos CodeBuild da pipeline."
  value = [
    aws_codebuild_project.template_validation.name,
    aws_codebuild_project.role_validation.name,
    aws_codebuild_project.dry_run.name,
    aws_codebuild_project.customer_managed_policies.name,
  ]
}
