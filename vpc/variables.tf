variable "vpc_name" {
  type        = string
  description = "VPC Name"
}

variable "cidr" {
  type        = string
  description = "VPC CIDR address"
}

variable "private_subnets" {
  type        = list(string)
  description = "VPC Private Subnets"
}

variable "public_subnets" {
  type        = list(string)
  description = "VPC Public Subnets"
}

variable "application" {
  type = string 
  description = "Application Name"
}

variable "environment" {
  type = string 
  description = "Environment"
}
