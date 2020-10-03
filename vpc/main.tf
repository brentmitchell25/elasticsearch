provider "aws" {
  region = "us-east-1"
}

data "aws_availability_zones" "all" {}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.55.0"
  name = var.vpc_name

  cidr = var.cidr

  azs             = data.aws_availability_zones.all.names
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets

  vpc_tags = {
    env = var.environment
    app = var.application
  }
}
