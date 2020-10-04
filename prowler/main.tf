data "aws_region" "current" {}

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
  name               = "prowler-ecs-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_policy.json
}

resource "aws_iam_role_policy" "prowler_logs" {
  name   = "prowler_logs_execution_policy"
  role   = aws_iam_role.prowler_role.id
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
  role       = module.ecs_task_definition.task_role_name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = module.ecs_task_definition.task_role_name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_cloudwatch_log_group" "prowler" {
  name              = "/ecs/${var.application}/prowler/${var.environment}"
  retention_in_days = 3

  tags = {
    env = var.environment
    app = var.application
  }
}

resource "aws_lambda_permission" "prowler_cloudwatch_allow" {
  statement_id  = "prowler_cloudwatch_allow"
  action        = "lambda:InvokeFunction"
  function_name = var.cloudwatch_lambda_arn
  principal     = "logs.${data.aws_region.current.name}.amazonaws.com"
  source_arn    = aws_cloudwatch_log_group.prowler.arn
}

resource "aws_cloudwatch_log_subscription_filter" "prowler_cloudwatch_logs_to_es" {
  depends_on      = [aws_lambda_permission.prowler_cloudwatch_allow]
  name            = "cloudwatch_logs_to_elasticsearch"
  log_group_name  = aws_cloudwatch_log_group.prowler.name
  filter_pattern  = ""
  destination_arn = var.cloudwatch_lambda_arn
}

module "ecs_task_definition" {
  source  = "umotif-public/ecs-fargate-task-definition/aws"
  version = "~> 2.0.0"

  enabled                   = true
  name_prefix               = "prowler"
  task_container_image      = "toniblyx/prowler:latest"
  cloudwatch_log_group_name = aws_cloudwatch_log_group.prowler.name

  task_container_command = ["-M", "json"]

  task_definition_cpu    = "256"
  task_definition_memory = "512"
  task_stop_timeout      = 120

  task_container_environment = {
    env = var.environment
    app = var.application
  }
}


module "ecs-fargate-scheduled-task" {
  source  = "umotif-public/ecs-fargate-scheduled-task/aws"
  version = "~> 1.0.0"

  name_prefix = "scheduled-task"

  ecs_cluster_arn = var.ecs_cluster_arn

  task_role_arn                 = module.ecs_task_definition.task_role_arn
  execution_role_arn            = module.ecs_task_definition.execution_role_arn
  event_target_assign_public_ip = true

  event_target_task_definition_arn = module.ecs_task_definition.task_definition_arn
  event_rule_schedule_expression   = "cron(0 12 * * ? *)"
  event_target_subnets             = var.subnet_ids
}
