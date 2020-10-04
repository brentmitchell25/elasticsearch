locals {
  environment = "prod"
  application = "fishtech"
}

module "network" {
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
  vpc_id                   = module.network.vpc_id
  cidr_block               = module.network.cidr_block
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
  subnets                  = module.network.public_subnets
  kibana_access            = true
}

module "bastion" {
  source = "../../bastion"

  application = local.application
  environment = local.environment
  subnets     = module.network.public_subnets
  vpc_id      = module.network.vpc_id
  key_name    = "fishtech"
}

module "cloudwatch_lambda" {
  source = "../../cloudwatch-logs"


  application        = local.application
  environment        = local.environment
  es_endpoint        = module.es_cluster.endpoint
  subnet_ids         = module.network.public_subnets
  security_group_ids = [module.network.default_security_group_id]
}

module "cloudtrail" {
  source = "../../cloudtrail"

  application           = local.application
  environment           = local.environment
  cloudwatch_lambda_arn = module.cloudwatch_lambda.arn
}

module "ecs_cluster" {
  source = "../../ecs-cluster"

  application = local.application
  environment = local.environment
}


module "hello_world_service" {
  source = "../../hello-world-service"

  application           = local.application
  environment           = local.environment
  subnets               = module.network.public_subnets
  container_ports       = [8080, 8081]
  vpc_id                = module.network.vpc_id
  cloudwatch_lambda_arn = module.cloudwatch_lambda.arn
  ecs_cluster           = module.ecs_cluster.cluster
}

module "prowler" {
  source = "../../prowler"


  application           = local.application
  environment           = local.environment
  cloudwatch_lambda_arn = module.cloudwatch_lambda.arn
  subnet_ids            = module.network.public_subnets
  ecs_cluster_arn       = module.ecs_cluster.cluster.arn
}
