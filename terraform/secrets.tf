# SPDX-License-Identifier: MIT
# Cross-account ExternalId shared secret.
#
# The CodeBuild projects source EXTERNAL_ID as a SECRETS_MANAGER-typed
# environment variable from this secret, instead of a plaintext
# EnvironmentVariable baked into the project. This keeps the shared secret
# out of CodeBuild project JSON (and CloudTrail PutProject events) and
# makes rotation a Secrets-Manager-only operation.

resource "aws_secretsmanager_secret" "external_id" {
  name        = "${var.naming_convention}/external-id"
  description = "Cross-account ExternalId shared secret used by the pipeline CodeBuild projects when assuming deploy-customer-managed-policy in member accounts."
}

resource "aws_secretsmanager_secret_version" "external_id" {
  secret_id     = aws_secretsmanager_secret.external_id.id
  secret_string = var.external_id
}
