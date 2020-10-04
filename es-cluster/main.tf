data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_iam_service_linked_role" "es" {
  aws_service_name = "es.amazonaws.com"
  custom_suffix    = var.environment
}

data "aws_iam_policy_document" "elasticsearch-log-publishing-policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:PutLogEventsBatch",
    ]

    resources = ["arn:aws:logs:*"]

    principals {
      identifiers = ["es.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "elasticsearch-log-publishing-policy" {
  policy_document = data.aws_iam_policy_document.elasticsearch-log-publishing-policy.json
  policy_name     = "elasticsearch-log-publishing-policy"
}

resource "aws_security_group" "elasticsearch" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    env = var.environment
    app = var.application
  }
}

resource "aws_elasticsearch_domain" "es" {
  domain_name           = var.environment
  elasticsearch_version = "6.8"

  dynamic "cluster_config" {
    for_each = [1]
    content {
      instance_count           = var.instance_count
      instance_type            = var.instance_type
      dedicated_master_enabled = var.dedicated_master_enabled
      dedicated_master_count   = var.dedicated_master_count
      dedicated_master_type    = var.dedicated_master_type
      zone_awareness_enabled   = var.zone_awareness_enabled

      dynamic "zone_awareness_config" {
        for_each = var.availability_zone_count > 1 ? [var.availability_zone_count] : []
        content {
          availability_zone_count = var.availability_zone_count
        }
      }
    }
  }

  ebs_options {
    ebs_enabled = var.ebs_enabled
    volume_size = var.ebs_volume_size
  }

  encrypt_at_rest {
    enabled = var.encrypt_at_rest_enabled
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  node_to_node_encryption {
    enabled = true
  }

  vpc_options {
    subnet_ids         = var.subnets
    security_group_ids = [aws_security_group.elasticsearch.id]
  }

  access_policies = data.aws_iam_policy_document.this.json

  log_publishing_options {
    log_type                 = "SEARCH_SLOW_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_slow_logs.arn
    enabled                  = "true"
  }

  log_publishing_options {
    log_type                 = "INDEX_SLOW_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_index_logs.arn
    enabled                  = "true"
  }

  log_publishing_options {
    log_type                 = "ES_APPLICATION_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_app_logs.arn
    enabled                  = "true"
  }

  tags = {
    env = var.environment
    app = var.application
  }

  depends_on = [
    aws_iam_service_linked_role.es
  ]
}

resource "aws_cloudwatch_log_group" "es_slow_logs" {
  name              = "/es/slow-logs-${var.environment}"
  retention_in_days = var.retention_in_days

  tags = {
    env = var.environment
    app = var.application
  }
}

resource "aws_cloudwatch_log_group" "es_index_logs" {
  name              = "/es/index-logs-${var.environment}"
  retention_in_days = var.retention_in_days

  tags = {
    env = var.environment
    app = var.application
  }
}

resource "aws_cloudwatch_log_group" "es_app_logs" {
  name              = "/es/app-logs-${var.environment}"
  retention_in_days = var.retention_in_days

  tags = {
    env = var.environment
    app = var.application
  }
}

data "aws_iam_policy_document" "this" {

  statement {
    effect  = "Allow"
    actions = ["es:*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = ["arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.environment}/*"]
  }
}
