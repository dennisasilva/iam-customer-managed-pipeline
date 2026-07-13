# SPDX-License-Identifier: MIT
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Variante Terraform do pipeline definido em cfn/cx-mng-pipeline.yaml.
# Mantém paridade com a arquitetura CloudFormation (6 estágios, StackSet role
# cross-account com ExternalId, bucket de artefatos endurecido).

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = var.region
}
