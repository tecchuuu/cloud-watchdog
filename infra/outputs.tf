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
