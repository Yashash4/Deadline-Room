terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# The region and account are deployment-specific; a deployer sets them in
# terraform.tfvars or via TF_VAR_ environment variables. No account id, key arn,
# or cluster name is hard-coded here.
provider "aws" {
  region = var.region
}
