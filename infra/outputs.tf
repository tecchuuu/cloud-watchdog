# Printed after `tofu apply`. Read them again any time with `tofu output`.

output "reports_bucket" {
  value = aws_s3_bucket.reports.bucket
}

output "findings_table" {
  value = aws_dynamodb_table.findings.name
}

output "actions_table" {
  value = aws_dynamodb_table.actions.name
}
