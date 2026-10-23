# SPDX-License-Identifier: MIT
# Projetos CodeBuild (paridade com os 4 projects do CFN).
#
# Nenhum arquivo em source/*.py do SourceOutput da branch rastreada e
# executado. Cada buildspec baixa um bundle imutavel de scripts
# (TRUSTED_SCRIPTS_*) pinando pela S3 version-id, verifica SHA-256 e so
# depois executa Python.

locals {
  codebuild_image = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"

  buildspec_template_validation = <<-EOT
    version: 0.2
    phases:
      build:
        commands:
          - echo "[INFO] [BUILD] Starting template validation process"
          - set -euo pipefail
          - TRUSTED_DIR="$(mktemp -d)"
          - BUNDLE="$TRUSTED_DIR/scripts.tar.gz"
          - aws s3api get-object --bucket "$TRUSTED_SCRIPTS_BUCKET" --key "$TRUSTED_SCRIPTS_KEY" --version-id "$TRUSTED_SCRIPTS_VERSION_ID" "$BUNDLE" >/dev/null
          - ACTUAL_SHA="$(sha256sum "$BUNDLE" | awk '{print $1}')"
          - test "$ACTUAL_SHA" = "$TRUSTED_SCRIPTS_SHA256" || { echo "[FATAL] trusted scripts sha256 mismatch" >&2; exit 1; }
          - mkdir -p "$TRUSTED_DIR/scripts" && tar -xzf "$BUNDLE" -C "$TRUSTED_DIR/scripts"
          - cd "$CODEBUILD_SRC_DIR"
          - python3 "$TRUSTED_DIR/scripts/validation/customer-managed-validation.py" --policies-folder './templates/customer-managed-policies/' --assignments-folder './templates/assignments/'
  EOT

  buildspec_role_validation = <<-EOT
    version: 0.2
    phases:
      build:
        commands:
          - echo "[INFO] [BUILD] Starting role validation process"
          - set -euo pipefail
          - TRUSTED_DIR="$(mktemp -d)"
          - BUNDLE="$TRUSTED_DIR/scripts.tar.gz"
          - aws s3api get-object --bucket "$TRUSTED_SCRIPTS_BUCKET" --key "$TRUSTED_SCRIPTS_KEY" --version-id "$TRUSTED_SCRIPTS_VERSION_ID" "$BUNDLE" >/dev/null
          - ACTUAL_SHA="$(sha256sum "$BUNDLE" | awk '{print $1}')"
          - test "$ACTUAL_SHA" = "$TRUSTED_SCRIPTS_SHA256" || { echo "[FATAL] trusted scripts sha256 mismatch" >&2; exit 1; }
          - mkdir -p "$TRUSTED_DIR/scripts" && tar -xzf "$BUNDLE" -C "$TRUSTED_DIR/scripts"
          - cd "$CODEBUILD_SRC_DIR"
          - python3 "$TRUSTED_DIR/scripts/validation/role-validation.py" --assignments-folder './templates/assignments/'
  EOT

  buildspec_dry_run = <<-EOT
    version: 0.2
    phases:
      build:
        commands:
          - echo "[INFO] [BUILD] Starting dry-run process"
          - set -euo pipefail
          - TRUSTED_DIR="$(mktemp -d)"
          - BUNDLE="$TRUSTED_DIR/scripts.tar.gz"
          - aws s3api get-object --bucket "$TRUSTED_SCRIPTS_BUCKET" --key "$TRUSTED_SCRIPTS_KEY" --version-id "$TRUSTED_SCRIPTS_VERSION_ID" "$BUNDLE" >/dev/null
          - ACTUAL_SHA="$(sha256sum "$BUNDLE" | awk '{print $1}')"
          - test "$ACTUAL_SHA" = "$TRUSTED_SCRIPTS_SHA256" || { echo "[FATAL] trusted scripts sha256 mismatch" >&2; exit 1; }
          - mkdir -p "$TRUSTED_DIR/scripts" && tar -xzf "$BUNDLE" -C "$TRUSTED_DIR/scripts"
          - cd "$CODEBUILD_SRC_DIR"
          - python3 "$TRUSTED_DIR/scripts/customer-managed-policies/customer-managed-deploy.py" --dry-run --state-bucket "$STATE_BUCKET"
  EOT

  buildspec_deploy = <<-EOT
    version: 0.2
    phases:
      build:
        commands:
          - echo "[INFO] [BUILD] Starting Customer Managed Policies process"
          - set -euo pipefail
          - TRUSTED_DIR="$(mktemp -d)"
          - BUNDLE="$TRUSTED_DIR/scripts.tar.gz"
          - aws s3api get-object --bucket "$TRUSTED_SCRIPTS_BUCKET" --key "$TRUSTED_SCRIPTS_KEY" --version-id "$TRUSTED_SCRIPTS_VERSION_ID" "$BUNDLE" >/dev/null
          - ACTUAL_SHA="$(sha256sum "$BUNDLE" | awk '{print $1}')"
          - test "$ACTUAL_SHA" = "$TRUSTED_SCRIPTS_SHA256" || { echo "[FATAL] trusted scripts sha256 mismatch" >&2; exit 1; }
          - mkdir -p "$TRUSTED_DIR/scripts" && tar -xzf "$BUNDLE" -C "$TRUSTED_DIR/scripts"
          - cd "$CODEBUILD_SRC_DIR"
          - python3 "$TRUSTED_DIR/scripts/customer-managed-policies/customer-managed-deploy.py" --state-bucket "$STATE_BUCKET"
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
      name  = "TRUSTED_SCRIPTS_BUCKET"
      value = var.trusted_scripts_bucket
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_KEY"
      value = var.trusted_scripts_key
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_VERSION_ID"
      value = var.trusted_scripts_version_id
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_SHA256"
      value = var.trusted_scripts_sha256
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
      name  = "TRUSTED_SCRIPTS_BUCKET"
      value = var.trusted_scripts_bucket
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_KEY"
      value = var.trusted_scripts_key
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_VERSION_ID"
      value = var.trusted_scripts_version_id
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_SHA256"
      value = var.trusted_scripts_sha256
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
      name  = "TRUSTED_SCRIPTS_BUCKET"
      value = var.trusted_scripts_bucket
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_KEY"
      value = var.trusted_scripts_key
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_VERSION_ID"
      value = var.trusted_scripts_version_id
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_SHA256"
      value = var.trusted_scripts_sha256
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
      name  = "TRUSTED_SCRIPTS_BUCKET"
      value = var.trusted_scripts_bucket
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_KEY"
      value = var.trusted_scripts_key
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_VERSION_ID"
      value = var.trusted_scripts_version_id
    }
    environment_variable {
      name  = "TRUSTED_SCRIPTS_SHA256"
      value = var.trusted_scripts_sha256
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = local.buildspec_deploy
  }

  tags = { Name = "Customer-Managed-Policies-CodeBuild-Project" }
}
