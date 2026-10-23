# SPDX-License-Identifier: MIT
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Variante Terraform do pipeline definido em cfn/cx-mng-pipeline.yaml.
# Mantém paridade com a arquitetura CloudFormation (6 estágios, StackSet role
# cross-account com ExternalId, bucket de artefatos endurecido).

terraform {
  # Upper-bound Terraform core to a known-tested minor series so a new major
  # (which can change state format / provider protocol) does not silently run.
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Keep the floor at 5.40 but cap at the next major. The authoritative
      # pin (exact version + h1/zh256 hashes) lives in .terraform.lock.hcl,
      # which MUST be committed. Regenerate with:
      #   terraform providers lock \
      #     -platform=linux_amd64 -platform=darwin_amd64 -platform=darwin_arm64
      version = ">= 5.40.0, < 6.0.0"
    }
  }
}

provider "aws" {
  region = var.region
}
