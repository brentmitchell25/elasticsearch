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
  name               = "lambda_elasticsearch_execution_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_policy.json
}

resource "aws_iam_role_policy" "lambda_elasticsearch_execution_policy" {
  name   = "lambda_elasticsearch_execution_policy"
  role   = aws_iam_role.lambda_elasticsearch_execution_role.id
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
  type        = "zip"
  source_file = "${path.module}/cwl2es.js"
  output_path = "${path.module}/cwl2eslambda.zip"
}

resource "aws_lambda_function" "cwl_stream_lambda" {
  filename         = "cwl2eslambda.zip"
  function_name    = "LogsToElasticsearch-${var.environment}"
  role             = aws_iam_role.lambda_elasticsearch_execution_role.arn
  handler          = "cwl2es.handler"
  timeout          = 60
  source_code_hash = filebase64sha256(data.archive_file.cwl2eslambda.output_path)
  runtime          = "nodejs10.x"

  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = var.security_group_ids
  }

  environment {
    variables = {
      ES_ENDPOINT = var.es_endpoint
    }
  }
}
