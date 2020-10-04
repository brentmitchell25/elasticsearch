variable "application" {
  type        = string
  description = "Application Name"
}

variable "environment" {
  type        = string
  description = "Environment"
}

variable "cloudwatch_lambda_arn" {
  type        = string
  description = "Lambda ARN to stream CloudWatch logs"
}
