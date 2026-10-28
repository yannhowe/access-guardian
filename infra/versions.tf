terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70.0, < 6.0.0"
    }
  }

  # Bucket, key, region, and DynamoDB lock table come from -backend-config.
  # Those values are repo variables. They are not written in this file.
  backend "s3" {}
}

provider "aws" {
  region = var.region
}
