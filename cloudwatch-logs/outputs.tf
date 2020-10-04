output "arn" {
  value       = aws_lambda_function.cwl_stream_lambda.arn
  description = "Lambda ARN"
}
