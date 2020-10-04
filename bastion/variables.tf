variable "application" {
  type        = string
  description = "Application Name"
}

variable "environment" {
  type        = string
  description = "Environment"
}

variable "vpc_id" {
  type        = string
  description = "VPC Id"
}

variable "subnets" {
  type        = list(string)
  description = "List of subnets"
}

variable "key_name" {
  type        = string
  description = "Key Pair Name"
}

variable "ami" {
  type        = string
  description = "AMI for host"
  default     = "ami-0947d2ba12ee1ff75"
}

variable "ssh_user" {
  type        = string
  description = "SSH User for host"
  default     = "ec2-user"
}
