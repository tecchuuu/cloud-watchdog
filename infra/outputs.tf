# Printed after `tofu apply`. Read them again any time with `tofu output`.

output "reports_bucket" {
  value = terraform_data.reports_bucket.output # same as the bucket name
}

output "findings_table" {
  value = aws_dynamodb_table.findings.name
}

output "actions_table" {
  value = aws_dynamodb_table.actions.name
}

output "scanner_function_name" {
  value = aws_lambda_function.scanner.function_name
}

output "actions_function_name" {
  description = "API Gateway's routes point at this Lambda (set up by hand)"
  value       = aws_lambda_function.actions.function_name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
