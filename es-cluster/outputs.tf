output "domain_name" {
  value       = aws_elasticsearch_domain.es.domain_name
  description = "Elasticsearch Domain Name"
}

output "endpoint" {
  value       = aws_elasticsearch_domain.es.endpoint
  description = "Elasticsearch Endpoint"
}

output "kibana_endpoint" {
  value       = aws_elasticsearch_domain.es.kibana_endpoint
  description = "Elasticsearch Kibana Endpoint"
}
