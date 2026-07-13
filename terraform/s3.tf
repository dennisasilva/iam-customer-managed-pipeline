# SPDX-License-Identifier: MIT
# Bucket de artefatos + state da pipeline.
# Paridade com CxMgrartifactsBucket do CFN: SSE-KMS (aws/s3), versionamento,
# BucketOwnerEnforced, Block Public Access total, lifecycle por prefixo e
# bucket policy (HTTPS-only + proteção do prefixo state/).

resource "aws_s3_bucket" "artifacts" {
  bucket = local.artifact_bucket_name
}

# ACLs desabilitadas bucket-wide; o dono do bucket é sempre dono do objeto.
resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-KMS com a chave gerenciada pela AWS (alias/aws/s3): não define
# kms_master_key_id de propósito, delegando a escolha da chave ao S3.
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  # Regra 1: artefatos do CodePipeline expiram em 90 dias. O prefixo aponta
  # só para o caminho do pipeline, então nunca casa com state/.
  rule {
    id     = "ExpirePipelineArtifacts"
    status = "Enabled"
    filter {
      prefix = "${var.naming_convention}-pipeline/"
    }
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # Regra 2: state/ é preservado. SEM expiração da versão atual (drift
  # detection depende disso). Versões antigas mantidas 365 dias.
  rule {
    id     = "PreserveState"
    status = "Enabled"
    filter {
      prefix = "state/"
    }
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "HTTPSOnly"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      # Só a role de deploy pode escrever/apagar em state/*. Torna o state
      # de drift confiável sem precisar de assinatura HMAC. Leituras não são
      # restringidas. Break-glass: um admin pode editar a policy à mão.
      {
        Sid       = "RestrictStateWritesToDeployRole"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action = [
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.artifacts.arn}/state/*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = aws_iam_role.customer_managed_policies.arn
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}
