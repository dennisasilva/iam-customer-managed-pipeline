data "aws_secretsmanager_secret" "repository_access_token" {
  name = var.secret_id
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}
