output "vpc_id" {
  value       = module.network.vpc_id
  description = "VPC Id"
}

output "domain_name" {
  value       = module.es_cluster.domain_name
  description = "Elasticsearch Domain Name"
}

output "endpoint" {
  value       = module.es_cluster.endpoint
  description = "Elasticsearch Endpoint"
}

output "kibana_endpoint" {
  value       = module.es_cluster.kibana_endpoint
  description = "Elasticsearch Kibana Endpoint"
}

output "bastion_ip" {
  value       = module.bastion.public_ip
  description = "Bastion Public IP"
}

output "dns_name" {
  value       = module.hello_world_service.dns_name
  description = "Hello World Service DNS"
}
