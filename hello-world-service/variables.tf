variable "application" {
  type        = string
  description = "Application Name"
}

variable "environment" {
  type        = string
  description = "Environment"
}

variable "subnets" {
  type        = list(string)
  description = "List of subnets to run scheduled task"
}

variable "container_ports" {
  type        = list(number)
  description = "List of container ports"
}

variable "vpc_id" {
  type        = string
  description = "VPC Id"
}

variable "cloudwatch_lambda_arn" {
  type        = string
  description = "CloudWatch Lambda ARN to stream logs"
}

variable "ecs_cluster" {
  description = "ECS cluster object"
  type = object({
    arn  = string
    name = string
  })
}
