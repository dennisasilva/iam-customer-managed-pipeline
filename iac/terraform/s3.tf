resource "aws_s3_bucket" "artifacts" {
  bucket = "${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}-cx-mng-artfcs"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
        bucket_key_enabled = true
      }
    }
  }

  public_access_block {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Sid       = "HTTPSOnly",
        Effect    = "Deny",
        Principal = "*",
        Action    = "s3:*",
        Resource  = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ],
        Condition = {
          Bool = {
            "aws:SecureTransport" = false
          }
        }
      }
    ]
  })
}
