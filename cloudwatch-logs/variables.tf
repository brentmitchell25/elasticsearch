variable "application" {
  type        = string
  description = "Application Name"
}

variable "environment" {
  type        = string
  description = "Environment"
}

variable "es_endpoint" {
  type        = string
  description = "Elasticsearch endpoint to send logs"
}

variable "subnet_ids" {
  type        = list(string)
  description = "List of subnets where the lambda should execute"
}

variable "security_group_ids" {
  type        = list(string)
  description = "List of security groups for the function"
}
