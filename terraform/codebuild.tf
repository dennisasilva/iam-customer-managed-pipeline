# SPDX-License-Identifier: MIT
# Projetos CodeBuild (paridade com os 4 projects do CFN).

locals {
  codebuild_image = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"

  buildspec_template_validation = <<-EOT
    version: 0.2
    phases:
      build:
        commands:
          - echo "[INFO] [BUILD] Starting template validation process"
          - cd source/validation/
          - chmod +x customer-managed-validation.py
          - python3 customer-managed-validation.py --policies-folder '../../templates/customer-managed-policies/' --assignments-folder '../../templates/assignments/'
  EOT

  buildspec_role_validation = <<-EOT
    version: 0.2
    phases:
      build:
        commands:
          - echo "[INFO] [BUILD] Starting role validation process"
          - cd source/validation/
          - chmod +x role-validation.py
          - python3 role-validation.py --assignments-folder '../../templates/assignments/'
  EOT

  buildspec_dry_run = <<-EOT
    version: 0.2
    phases:
      build:
        commands:
          - echo "[INFO] [BUILD] Starting dry-run process"
          - cd source/customer-managed-policies/
          - chmod +x customer-managed-deploy.py
          - python3 customer-managed-deploy.py --dry-run --state-bucket $STATE_BUCKET
  EOT

  buildspec_deploy = <<-EOT
    version: 0.2
    phases:
      build:
        commands:
          - echo "[INFO] [BUILD] Starting Customer Managed Policies process"
          - cd source/customer-managed-policies/
          - chmod +x customer-managed-deploy.py
          - python3 customer-managed-deploy.py --state-bucket $STATE_BUCKET
  EOT
}

resource "aws_codebuild_project" "template_validation" {
  name         = "${var.naming_convention}-template-validation"
  service_role = aws_iam_role.template_validation.arn

  artifacts { type = "CODEPIPELINE" }

  environment {
    type         = "LINUX_CONTAINER"
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = local.codebuild_image
    environment_variable {
      name  = "TZ"
      value = "America/Sao_Paulo"
    }
    environment_variable {
      name  = "REGION"
      value = local.region
    }
    environment_variable {
      name  = "ALLOWED_ACCOUNT_IDS"
      value = join(",", var.allowed_account_ids)
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = local.buildspec_template_validation
  }

  tags = { Name = "Template-Validation-CodeBuild-Project" }
}

resource "aws_codebuild_project" "role_validation" {
  name         = "${var.naming_convention}-role-validation"
  service_role = aws_iam_role.role_validation.arn

  artifacts { type = "CODEPIPELINE" }

  environment {
    type         = "LINUX_CONTAINER"
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = local.codebuild_image
    environment_variable {
      name  = "TZ"
      value = "America/Sao_Paulo"
    }
    environment_variable {
      name  = "EXTERNAL_ID"
      value = var.external_id
    }
    environment_variable {
      name  = "ALLOWED_ACCOUNT_IDS"
      value = join(",", var.allowed_account_ids)
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = local.buildspec_role_validation
  }

  tags = { Name = "Role-Validation-CodeBuild-Project" }
}

resource "aws_codebuild_project" "dry_run" {
  name         = "${var.naming_convention}-dry-run"
  service_role = aws_iam_role.customer_managed_policies.arn

  artifacts { type = "CODEPIPELINE" }

  environment {
    type         = "LINUX_CONTAINER"
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = local.codebuild_image
    environment_variable {
      name  = "TZ"
      value = "America/Sao_Paulo"
    }
    environment_variable {
      name  = "STATE_BUCKET"
      value = aws_s3_bucket.artifacts.id
    }
    environment_variable {
      name  = "EXTERNAL_ID"
      value = var.external_id
    }
    environment_variable {
      name  = "ALLOWED_ACCOUNT_IDS"
      value = join(",", var.allowed_account_ids)
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = local.buildspec_dry_run
  }

  tags = { Name = "DryRun-CodeBuild-Project" }
}

resource "aws_codebuild_project" "customer_managed_policies" {
  name         = "${var.naming_convention}-customer-managed-policies"
  service_role = aws_iam_role.customer_managed_policies.arn

  artifacts { type = "CODEPIPELINE" }

  environment {
    type         = "LINUX_CONTAINER"
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = local.codebuild_image
    environment_variable {
      name  = "TZ"
      value = "America/Sao_Paulo"
    }
    environment_variable {
      name  = "REGION"
      value = local.region
    }
    environment_variable {
      name  = "STATE_BUCKET"
      value = aws_s3_bucket.artifacts.id
    }
    environment_variable {
      name  = "EXTERNAL_ID"
      value = var.external_id
    }
    environment_variable {
      name  = "ALLOWED_ACCOUNT_IDS"
      value = join(",", var.allowed_account_ids)
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = local.buildspec_deploy
  }

  tags = { Name = "Customer-Managed-Policies-CodeBuild-Project" }
}
