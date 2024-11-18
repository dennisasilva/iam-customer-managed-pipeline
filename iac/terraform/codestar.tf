resource "aws_codestarconnections_connection" "github" {
  provider_type   = "GitHub"
  connection_name = "${var.naming_convention}-github"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_codestarconnections_connection" "gitlab" {
  provider_type   = "GitLab"
  connection_name = "${var.naming_convention}-gitlab"

  lifecycle {
    create_before_destroy = true
  }
}
