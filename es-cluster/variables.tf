variable "environment" {
  type        = string
  description = "Environment"
}

variable "vpc_id" {
  type        = string
  description = "VPC Id"
}

variable "cidr_block" {
  type        = string
  description = "VPC CIDR block"
}

variable "retention_in_days" {
  type        = number
  description = "CloudWatch Log Retention"
}

variable "instance_count" {
  type        = number
  description = "Instance Count"
}

variable "instance_type" {
  type        = string
  description = "Instance Type"
}

variable "dedicated_master_enabled" {
  type        = bool
  description = "Enable Dedicated Master"
}

variable "dedicated_master_count" {
  type        = number
  description = "Dedicated Master Count"
  default     = 0
}

variable "dedicated_master_type" {
  type        = string
  description = "Dedicated Master Instance Type"
  default     = ""
}

variable "zone_awareness_enabled" {
  type        = bool
  description = "Enable Zone Awareness"
}

variable "availability_zone_count" {
  type        = number
  description = "Availability Zone Count"
}

variable "ebs_enabled" {
  type        = bool
  description = "Enable EBS"
}

variable "ebs_volume_size" {
  type        = number
  description = "EBS Volume Size"
}

variable "encrypt_at_rest_enabled" {
  type        = bool
  description = "Encrypt at Rest"
}

variable "subnets" {
  type        = list(string)
  description = ""
}

variable "kibana_access" {
  type        = bool
  description = "Kibana Access"
}

variable "application" {
  type        = string
  description = "Application Name"
}
