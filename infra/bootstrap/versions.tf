# One-off bootstrap, applied once by an account admin with local state
# (git-ignored): the remote state bucket and the permissions boundary every
# CI role must carry. CI never holds permissions to change either.
terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.66"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project    = "secpipe"
      owner      = var.owner
      managed-by = "terraform-bootstrap"
    }
  }
}
