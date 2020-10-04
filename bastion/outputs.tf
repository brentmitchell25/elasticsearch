output "public_ip" {

  value       = module.bastion.public_ip
  description = "Public IP of bastion host"
}
