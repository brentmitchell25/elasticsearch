output "dns_name" {
  value       = aws_lb.alb.dns_name
  description = "Hello World Service DNS"
}
