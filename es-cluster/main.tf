provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_service_linked_role" "es" {
  aws_service_name = "es.amazonaws.com"
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

  dynamic "cognito_options" {
    for_each = var.kibana_access == true ? [{}] : []
    content {
      enabled          = true
      user_pool_id     = aws_cognito_user_pool.kibana_user_pool[0].id
      identity_pool_id = aws_cognito_identity_pool.kibana_identity_pool[0].id
      role_arn         = aws_iam_role.kibana_cognito_role[0].arn
    }
  }

  tags = {
    env = var.environment
    app = var.application
  }

  depends_on = [
    aws_iam_role_policy_attachment.kibana_cognito_role_policy, aws_iam_service_linked_role.es
  ]
}

resource "aws_cloudwatch_log_group" "es_slow_logs" {
  name = "slow-logs"
  retention_in_days = var.retention_in_days

  tags = {
    env = var.environment
    app = var.application
  }
}

resource "aws_cloudwatch_log_group" "es_index_logs" {
  name = "index-logs"
  retention_in_days = var.retention_in_days

  tags = {
    env = var.environment
    app = var.application
  }
}

resource "aws_cloudwatch_log_group" "es_app_logs" {
  name = "app-logs"
  retention_in_days = var.retention_in_days

  tags = {
    env = var.environment
    app = var.application
  }
}

data "aws_iam_policy_document" "this" {

  dynamic "statement" {
    for_each = var.kibana_access == true ? [{}] : []
    content {
      effect  = "Allow"
      actions = ["es:*"]
      principals {
        type = "AWS"
        identifiers = [
          "arn:aws:iam::${var.account_number}:role/${aws_iam_role.kibana_cognito_role[0].name}",
          "arn:aws:iam::${var.account_number}:role/${aws_iam_role.cognito_auth_role[0].name}"
        ]
      }
      resources = ["arn:aws:es:${var.region}:${var.account_number}:domain/${var.environment}/*"]
    }
  }
}


resource "aws_cognito_user_pool" "kibana_user_pool" {
  count = var.kibana_access == true ? 1 : 0
  name  = var.application

  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

}

resource "aws_cognito_identity_pool" "kibana_identity_pool" {
  count                            = var.kibana_access == true ? 1 : 0
  identity_pool_name               = var.application
  allow_unauthenticated_identities = false
}

data "aws_iam_policy" "kibana_cognito_policy" {
  count = var.kibana_access == true ? 1 : 0
  arn   = "arn:aws:iam::aws:policy/AmazonESCognitoAccess"
}

data "aws_iam_policy_document" "elasticsearch_cognito_trust_policy_doc" {
  count = var.kibana_access == true ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }

    effect = "Allow"
  }
}

resource "aws_cognito_user_pool_domain" "this" {
  count        = var.kibana_access == true ? 1 : 0
  domain       = var.application
  user_pool_id = aws_cognito_user_pool.kibana_user_pool[0].id
}

resource "aws_iam_role" "kibana_cognito_role" {
  count              = var.kibana_access == true ? 1 : 0
  name               = "${var.application}-kibana"
  assume_role_policy = data.aws_iam_policy_document.elasticsearch_cognito_trust_policy_doc[0].json
}

resource "aws_iam_role_policy_attachment" "kibana_cognito_role_policy" {
  count      = var.kibana_access == true ? 1 : 0
  role       = aws_iam_role.kibana_cognito_role[0].name
  policy_arn = data.aws_iam_policy.kibana_cognito_policy[0].arn
}

data "aws_iam_policy_document" "cognito_auth_policy_doc" {
  count = var.kibana_access == true ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "mobileanalytics:PutEvents",
      "cognito-sync:*",
      "cognito-identity:*",
      "es:ESHttp*"
    ]
    resources = ["arn:aws:es:${var.region}:${var.account_number}:domain/${var.environment}/*"]

  }
}

data "aws_iam_policy_document" "cognito_auth_trust_relationship_policy_doc" {
  count = var.kibana_access == true ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRoleWithWebIdentity"
    ]
    principals {
      type        = "Federated"
      identifiers = ["cognito-identity.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "cognito-identity.amazonaws.com:aud"

      values = [
        aws_cognito_identity_pool.kibana_identity_pool[0].id
      ]
    }
    condition {
      test     = "ForAnyValue:StringLike"
      variable = "cognito-identity.amazonaws.com:amr"

      values = [
        "authenticated"
      ]
    }
  }
}

resource "aws_iam_policy" "cognito_auth_policy" {
  count       = var.kibana_access == true ? 1 : 0
  name        = var.application
  path        = "/"
  description = "Authorizaation policy for kibana cognito identity pool"

  policy = data.aws_iam_policy_document.cognito_auth_policy_doc[0].json

}

resource "aws_iam_role" "cognito_auth_role" {
  count = var.kibana_access == true ? 1 : 0
  name  = "${var.application}-cognito"

  assume_role_policy = data.aws_iam_policy_document.cognito_auth_trust_relationship_policy_doc[0].json
}

resource "aws_iam_role_policy_attachment" "cognito_auth_role_policy" {
  count      = var.kibana_access == true ? 1 : 0
  role       = aws_iam_role.cognito_auth_role[0].name
  policy_arn = aws_iam_policy.cognito_auth_policy[0].arn
}

resource "aws_cognito_identity_pool_roles_attachment" "this" {
  count            = var.kibana_access == true ? 1 : 0
  identity_pool_id = aws_cognito_identity_pool.kibana_identity_pool[0].id

  roles = {
    "authenticated" = aws_iam_role.cognito_auth_role[0].arn
  }
}
