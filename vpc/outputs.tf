output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.vpc.vpc_id
}

output "cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnets" {
  description = "Private Subnets of VPC"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "Public Subnets of VPC"
  value       = module.vpc.public_subnets
}

output "default_security_group_id" {
  description = "Default security group of VPC"
  value       = module.vpc.default_security_group_id
}
