data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_security_group" "lb_sg" {
  name   = "lb-${var.application}-${var.environment}"
  vpc_id = var.vpc_id
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
  count             = length(var.container_ports)
  security_group_id = aws_security_group.lb_sg.id

  type        = "ingress"
  from_port   = element(var.container_ports, count.index)
  to_port     = element(var.container_ports, count.index)
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_lb" "alb" {
  name               = "${var.application}-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.subnets
  security_groups    = [aws_security_group.lb_sg.id]
}

resource "aws_lb_listener" "http" {
  count = length(var.container_ports)

  load_balancer_arn = aws_lb.alb.id
  port              = element(var.container_ports, count.index)
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_lb_target_group.http[count.index].id
    type             = "forward"
  }
}

resource "aws_lb_target_group" "http" {
  count = length(var.container_ports)

  name     = "${var.application}-${var.environment}-${var.container_ports[count.index]}"
  port     = element(var.container_ports, count.index)
  protocol = "HTTP"

  vpc_id      = var.vpc_id
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
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
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

module "ecs_service" {
  source  = "trussworks/ecs-service/aws"
  version = "5.0.0"

  name        = var.application
  environment = var.environment

  associate_alb = true

  alb_security_group = aws_security_group.lb_sg.id

  hello_world_container_ports = var.container_ports

  lb_target_groups = [
    {
      lb_target_group_arn         = aws_lb_target_group.http[0].arn
      container_port              = element(var.container_ports, 0)
      container_health_check_port = element(var.container_ports, 0)
    },
    {
      lb_target_group_arn         = aws_lb_target_group.http[1].arn
      container_port              = element(var.container_ports, 0)
      container_health_check_port = element(var.container_ports, 1)
    }
  ]

  ecs_cluster      = var.ecs_cluster
  ecs_subnet_ids   = var.subnets
  ecs_vpc_id       = var.vpc_id
  ecs_use_fargate  = true
  assign_public_ip = true

  kms_key_id = aws_kms_key.cluster_kms.arn
}

resource "aws_lambda_permission" "ecs_service_cloudwatch_allow" {
  statement_id  = "cloudwatch_allow"
  action        = "lambda:InvokeFunction"
  function_name = var.cloudwatch_lambda_arn
  principal     = "logs.${data.aws_region.current.name}.amazonaws.com"
  source_arn    = module.ecs_service.awslogs_group_arn
}

resource "aws_cloudwatch_log_subscription_filter" "cloudwatch_logs_to_es" {
  depends_on      = [aws_lambda_permission.ecs_service_cloudwatch_allow]
  name            = "cloudwatch_logs_to_elasticsearch"
  log_group_name  = module.ecs_service.awslogs_group
  filter_pattern  = ""
  destination_arn = var.cloudwatch_lambda_arn
}

