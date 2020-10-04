provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

locals {
  environment = "test"
  application = "fishtech"
  region      = "us-east-1"
  hello_world_container_ports = [8080, 8081]
}

module "test_network" {
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
  vpc_id                   = module.test_network.vpc_id
  cidr_block               = "0.0.0.0/0"
  instance_count           = 1
  instance_type            = "t3.small.elasticsearch"
  dedicated_master_enabled = false
  zone_awareness_enabled   = false
  availability_zone_count  = 1
  ebs_enabled              = true
  retention_in_days        = 3
  ebs_volume_size          = 10
  encrypt_at_rest_enabled  = true
  subnets                  = [module.test_network.public_subnets[0]]
  kibana_access            = true
  region                   = local.region
  account_number           = "116722176476"
}

resource "aws_security_group" "bastion_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"
  vpc_id      = module.test_network.vpc_id

  ingress {
    description = "SSH to VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    env = local.environment
    app = local.application
  }
}

module "bastion" {
  source    = "cloudposse/ec2-bastion-server/aws"
  name      = "fishtech-bastion"
  namespace = "bastion"
  ssh_user  = "ec2-user"
  stage     = local.environment
  subnets   = module.test_network.public_subnets
  vpc_id    = module.test_network.vpc_id
  key_name  = "fishtech"
  ami       = "ami-0947d2ba12ee1ff75"
  security_groups = [aws_security_group.bastion_ssh.id]
}



data "aws_iam_policy_document" "cloudwatch_logs_allow_kms" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      ]
    }

    actions = [
      "kms:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Allow logs KMS access"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "cluster_kms" {
  description         = "Key for ECS log encryption"
  enable_key_rotation = true

  policy = data.aws_iam_policy_document.cloudwatch_logs_allow_kms.json
}

## Lambda Permissions for Cloudwatch logs

data "aws_iam_policy_document" "lambda_assume_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_elasticsearch_execution_role" {
  name = "lambda_elasticsearch_execution_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_policy.json
}

resource "aws_iam_role_policy" "lambda_elasticsearch_execution_policy" {
  name = "lambda_elasticsearch_execution_policy"
  role = aws_iam_role.lambda_elasticsearch_execution_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:*:*:*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "es:ESHttpPost",
      "Resource": "arn:aws:es:*:*:*"
    }
  ]
}
EOF
}

data "archive_file" "cwl2eslambda" {
  type = "zip"
  source_file = "cwl2es.js"
  output_path = "cwl2eslambda.zip"
}

resource "aws_lambda_function" "cwl_stream_lambda" {
  filename         = "cwl2eslambda.zip"
  function_name    = "LogsToElasticsearch"
  role             = aws_iam_role.lambda_elasticsearch_execution_role.arn
  handler          = "cwl2es.handler"
  timeout = 60
  source_code_hash = filebase64sha256(data.archive_file.cwl2eslambda.output_path)
  runtime          = "nodejs10.x"

  vpc_config {
    subnet_ids         = module.test_network.public_subnets
    security_group_ids = [module.test_network.default_security_group_id]
  }

  environment {
    variables = {
      ES_ENDPOINT = module.es_cluster.endpoint
    }
  }
}

resource "aws_lambda_permission" "ecs_service_cloudwatch_allow" {
  statement_id = "cloudwatch_allow"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cwl_stream_lambda.arn
  principal = "logs.${local.region}.amazonaws.com"
  source_arn = module.ecs_service.awslogs_group_arn
}

resource "aws_cloudwatch_log_subscription_filter" "cloudwatch_logs_to_es" {
  depends_on = [aws_lambda_permission.ecs_service_cloudwatch_allow]
  name            = "cloudwatch_logs_to_elasticsearch"
  log_group_name  = module.ecs_service.awslogs_group
  filter_pattern  = ""
  destination_arn = aws_lambda_function.cwl_stream_lambda.arn
}

resource "aws_ecs_cluster" "cluster" {
  name = local.application
}

#
# ALB
#
resource "aws_security_group" "lb_sg" {
  name   = "lb-${local.application}"
  vpc_id = module.test_network.vpc_id
}

resource "aws_security_group_rule" "app_lb_allow_outbound" {
  security_group_id = aws_security_group.lb_sg.id

  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "app_lb_allow_all_http" {
  count             = length(local.hello_world_container_ports)
  security_group_id = aws_security_group.lb_sg.id

  type        = "ingress"
  from_port   = element(local.hello_world_container_ports, count.index)
  to_port     = element(local.hello_world_container_ports, count.index)
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_lb" "alb" {
  name               = local.application
  internal           = false
  load_balancer_type = "application"
  subnets            = module.test_network.public_subnets
  security_groups    = [aws_security_group.lb_sg.id]
}

resource "aws_lb_listener" "http" {
  count = length(local.hello_world_container_ports)

  load_balancer_arn = aws_lb.alb.id
  port              = element(local.hello_world_container_ports, count.index)
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_lb_target_group.http[count.index].id
    type             = "forward"
  }
}

resource "aws_lb_target_group" "http" {
  count = length(local.hello_world_container_ports)

  name     = "${local.application}-${local.hello_world_container_ports[count.index]}"
  port     = element(local.hello_world_container_ports, count.index)
  protocol = "HTTP"

  vpc_id      = module.test_network.vpc_id
  target_type = "ip"

  deregistration_delay = 90

  health_check {
    timeout             = 5
    interval            = 30
    path                = "/"
    protocol            = "HTTP"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200"
  }

  depends_on = [aws_lb.alb]
}


#
# ECS Service
#
module "ecs_service" {
  source = "trussworks/ecs-service/aws"
  version = "5.0.0"

  name        = local.application
  environment = local.environment

  associate_alb = true

  alb_security_group     = aws_security_group.lb_sg.id

  hello_world_container_ports = local.hello_world_container_ports

  lb_target_groups = [
    {
      lb_target_group_arn         = aws_lb_target_group.http[0].arn
      container_port              = element(local.hello_world_container_ports, 0)
      container_health_check_port = element(local.hello_world_container_ports, 0)
    },
    {
      lb_target_group_arn         = aws_lb_target_group.http[1].arn
      container_port              = element(local.hello_world_container_ports, 0)
      container_health_check_port = element(local.hello_world_container_ports, 1)
    }
  ]

  ecs_cluster      = aws_ecs_cluster.cluster
  ecs_subnet_ids   = module.test_network.public_subnets
  ecs_vpc_id       = module.test_network.vpc_id
  ecs_use_fargate  = true
  assign_public_ip = true

  kms_key_id = aws_kms_key.cluster_kms.arn
}

## Prowler
data "aws_iam_policy_document" "ecs_assume_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}


resource "aws_iam_role" "prowler_role" {
  name = "prowler-ecs-${local.environment}"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_policy.json
}

resource "aws_iam_role_policy" "prowler_logs" {
  name = "prowler_logs_execution_policy"
  role = aws_iam_role.prowler_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:*:*:*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  #role       = aws_iam_role.prowler_role.name
  role       = module.ecs-task-definition.task_role_name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = module.ecs-task-definition.task_role_name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_cloudwatch_log_group" "prowler" {
  name = "/ecs/${local.application}/prowler/${local.environment}"
  retention_in_days = 3

  tags = {
    env = local.environment
    app = local.application
  }
}

resource "aws_lambda_permission" "prowler_cloudwatch_allow" {
  statement_id = "prowler_cloudwatch_allow"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cwl_stream_lambda.arn
  principal = "logs.${local.region}.amazonaws.com"
  source_arn = aws_cloudwatch_log_group.prowler.arn
}

resource "aws_cloudwatch_log_subscription_filter" "prowler_cloudwatch_logs_to_es" {
  depends_on = [aws_lambda_permission.prowler_cloudwatch_allow]
  name            = "cloudwatch_logs_to_elasticsearch"
  log_group_name  = aws_cloudwatch_log_group.prowler.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.cwl_stream_lambda.arn
}

module "ecs-task-definition" {
  source = "umotif-public/ecs-fargate-task-definition/aws"
  version = "~> 2.0.0"

  enabled              = true
  name_prefix          = "prowler"
  task_container_image = "toniblyx/prowler:latest"
  cloudwatch_log_group_name = aws_cloudwatch_log_group.prowler.name

  task_container_command = ["-M", "json"]

  task_definition_cpu    = "256"
  task_definition_memory = "512"
  task_stop_timeout  = 120

  task_container_environment = {
    env = local.environment
  }
}


module "ecs-fargate-scheduled-task" {
  source = "umotif-public/ecs-fargate-scheduled-task/aws"
  version = "~> 1.0.0"

  name_prefix = "scheduled-task"

  ecs_cluster_arn = aws_ecs_cluster.cluster.arn

  task_role_arn      = module.ecs-task-definition.task_role_arn
  execution_role_arn = module.ecs-task-definition.execution_role_arn
  event_target_assign_public_ip = true

  event_target_task_definition_arn = module.ecs-task-definition.task_definition_arn
  event_rule_schedule_expression   = "cron(0 12 * * ? *)"
  event_target_subnets             = module.test_network.public_subnets
}


## Cloudtrail
resource "aws_cloudtrail" "trail" {
  name                          = "fishtech-trail-${local.environment}"
  s3_bucket_name                = aws_s3_bucket.log_bucket.id
  include_global_service_events = false
  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn = aws_iam_role.cloudtrail_elasticsearch_execution_role.arn
}

resource "aws_s3_bucket" "log_bucket" {
  bucket        = "mitchell-fishtech-cloudtrail-logs-${local.environment}"
  force_destroy = true

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::mitchell-fishtech-cloudtrail-logs-${local.environment}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mitchell-fishtech-cloudtrail-logs-${local.environment}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

data "aws_iam_policy_document" "cloudtrail_assume_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_elasticsearch_execution_role" {
  name = "cloudtrail_elasticsearch_execution_role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_policy.json
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name = "cloudtrail_logs_execution_policy"
  role = aws_iam_role.cloudtrail_elasticsearch_execution_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:*:*:*"
      ]
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name = "/cloudtrail-${local.environment}"
  retention_in_days = 3

  tags = {
    env = local.environment
    app = local.application
  }
}

resource "aws_lambda_permission" "cloudtrail_cloudwatch_allow" {
  statement_id = "cloudtrail_cloudwatch_allow"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cwl_stream_lambda.arn
  principal = "logs.${local.region}.amazonaws.com"
  source_arn = aws_cloudwatch_log_group.cloudtrail.arn
}

resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_cloudwatch_logs_to_es" {
  depends_on = [aws_lambda_permission.cloudtrail_cloudwatch_allow]
  name            = "cloudwatch_logs_to_elasticsearch"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.cwl_stream_lambda.arn
}
