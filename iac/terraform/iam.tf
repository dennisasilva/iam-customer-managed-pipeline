resource "aws_iam_role" "codebuild_template_validation" {
  name        = "${var.naming_convention}-template-validation"
  description = "CodeBuild role for Template Validation CodeBuild Project"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "codebuild.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
    ]
  })

  inline_policy {
    name   = "CodeBuildPolicy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
          Resource = "*",
        },
        {
          Effect   = "Allow"
          Action   = ["codecommit:GitPull"],
          Resource = "*",
        },
        {
          Effect   = "Allow"
          Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:AbortMultipartUpload"],
          Resource = "*",
        },
      ],
    })
  }
}

resource "aws_iam_role" "codebuild_customer_managed_policies" {
  name        = "${var.naming_convention}-customer-managed-policies"
  description = "CodeBuild role for Customer Managed Policies CodeBuild Project"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "codebuild.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
    ]
  })

  inline_policy {
    name   = "CodeBuildPolicy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
          Resource = "*",
        },
        {
          Effect   = "Allow"
          Action   = ["codecommit:GitPull"],
          Resource = "*",
        },
        {
          Effect   = "Allow"
          Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
          Resource = "*",
        },
        {
          Effect   = "Allow"
          Action   = ["sts:AssumeRole"],
          Resource = "arn:aws:iam::*:role/deploy-customer-managed-policy",
        },
      ],
    })
  }
}
