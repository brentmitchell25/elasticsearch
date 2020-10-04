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
  description = "CloudWatch Lambda ARN to stream logs"
}

variable "subnet_ids" {
  type        = list(string)
  description = "List of subnets to run scheduled task"
}

variable "ecs_cluster_arn" {
  type        = string
  description = "ECS Cluster ARN"
}
