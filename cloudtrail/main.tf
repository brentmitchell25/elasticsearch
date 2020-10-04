data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "trail" {
  name                          = "fishtech-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.log_bucket.id
  include_global_service_events = false
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_elasticsearch_execution_role.arn
}

resource "aws_s3_bucket" "log_bucket" {
  bucket        = "mitchell-fishtech-cloudtrail-logs-${var.environment}"
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
            "Resource": "arn:aws:s3:::mitchell-fishtech-cloudtrail-logs-${var.environment}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mitchell-fishtech-cloudtrail-logs-${var.environment}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
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
  name               = "cloudtrail_elasticsearch_execution_role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_policy.json
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name   = "cloudtrail_logs_execution_policy"
  role   = aws_iam_role.cloudtrail_elasticsearch_execution_role.id
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
  name              = "/cloudtrail-${var.environment}"
  retention_in_days = 3

  tags = {
    env = var.environment
    app = var.application
  }
}

resource "aws_lambda_permission" "cloudtrail_cloudwatch_allow" {
  statement_id  = "cloudtrail_cloudwatch_allow"
  action        = "lambda:InvokeFunction"
  function_name = var.cloudwatch_lambda_arn
  principal     = "logs.${data.aws_region.current.name}.amazonaws.com"
  source_arn    = aws_cloudwatch_log_group.cloudtrail.arn
}

resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_cloudwatch_logs_to_es" {
  depends_on      = [aws_lambda_permission.cloudtrail_cloudwatch_allow]
  name            = "cloudwatch_logs_to_elasticsearch"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern  = ""
  destination_arn = var.cloudwatch_lambda_arn
}
