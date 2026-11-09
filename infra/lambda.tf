# Lambda: the scanner (lambda/scanner.py) running in AWS.
# The actions Lambda (Fix / Delete / Ignore) is added here later.

# Zip scanner.py. When the file changes, the hash changes and `tofu apply` uploads it again.
data "archive_file" "scanner" {
  type        = "zip"
  source_file = "${path.module}/../lambda/scanner.py"
  output_path = "${path.module}/build/scanner.zip"
}

resource "aws_lambda_function" "scanner" {
  function_name    = "watchdog-scanner"
  role             = local.lab_role_arn
  runtime          = "python3.12"
  handler          = "scanner.lambda_handler" # file scanner.py, function lambda_handler
  filename         = data.archive_file.scanner.output_path
  source_code_hash = data.archive_file.scanner.output_base64sha256
  timeout          = 120 # seconds; two regions + CloudWatch calls per instance
  memory_size      = 256

  # The same settings you exported by hand in CloudShell.
  environment {
    variables = {
      REGIONS          = join(",", var.regions)
      FINDINGS_TABLE   = aws_dynamodb_table.findings.name
      REPORTS_BUCKET   = terraform_data.reports_bucket.output
      SNS_TOPIC_ARN    = aws_sns_topic.alerts.arn
      IDLE_HOURS       = tostring(var.idle_hours)
      IDLE_CPU_PERCENT = "5"
    }
  }

  depends_on = [aws_cloudwatch_log_group.scanner]
}

# Where print() output goes. Made here (not by Lambda on first run)
# so it has a retention limit and `tofu destroy` removes it.
resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/watchdog-scanner"
  retention_in_days = 14
}

# If the daily run fails, don't retry it twice (Lambda's default for scheduled
# calls). One failure is enough for the alarm, and retries would rescan for nothing.
resource "aws_lambda_function_event_invoke_config" "scanner" {
  function_name          = aws_lambda_function.scanner.function_name
  maximum_retry_attempts = 0
}
