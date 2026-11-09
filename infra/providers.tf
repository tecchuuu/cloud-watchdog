# Which plugins OpenTofu needs, and how to talk to AWS.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource OpenTofu creates gets this tag automatically.
  # The scanner skips anything tagged managed-by=watchdog,
  # so the Watchdog never reports (or "fixes") its own parts.
  default_tags {
    tags = {
      managed-by = "watchdog"
      project    = "cloud-watchdog"
    }
  }
}
