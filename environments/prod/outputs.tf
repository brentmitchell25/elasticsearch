output "vpc_id" {
  value       = module.prod_network.vpc_id
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
