# SPDX-License-Identifier: MIT
# Conexão CodeStar — cria GitHub OU GitLab conforme var.repository_type.
# Após o apply, a conexão nasce PENDING; conclua o handshake OAuth no console
# (Developer Tools > Connections) para que fique AVAILABLE.

resource "aws_codestarconnections_connection" "github" {
  count         = local.is_github ? 1 : 0
  name          = "${var.naming_convention}-gitHub"
  provider_type = "GitHub"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_codestarconnections_connection" "gitlab" {
  count         = local.is_github ? 0 : 1
  name          = "${var.naming_convention}-gitLab"
  provider_type = "GitLab"

  lifecycle {
    create_before_destroy = true
  }
}
