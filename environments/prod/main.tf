locals {
  environment = "prod"
  application = "fishtech"
}

module "prod_network" {
  source = "../../vpc"

  vpc_name        = "fishtech"
  cidr            = "10.0.0.0/16"
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
  application     = local.application
  environment     = local.environment
}

module "es_cluster" {
  source = "../../es-cluster"

  application              = local.application
  environment              = local.environment
  vpc_id                   = module.prod_network.vpc_id
  cidr_block               = module.prod_network.cidr_block
  instance_count           = 2
  instance_type            = "t3.small.elasticsearch"
  dedicated_master_count   = 3
  dedicated_master_type    = "t3.small.elasticsearch"
  dedicated_master_enabled = true
  zone_awareness_enabled   = true
  availability_zone_count  = 2
  ebs_enabled              = true
  retention_in_days        = 7
  ebs_volume_size          = 10
  encrypt_at_rest_enabled  = true
  subnets                  = module.prod_network.public_subnets
  kibana_access            = true
  region                   = "us-east-1"
  account_number           = "116722176476"
}
