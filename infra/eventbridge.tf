# EventBridge: run the scanner on a schedule (default once a day).
# Three pieces, and all three are needed:

# 1. When: the schedule.
resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "watchdog-daily-scan"
  description         = "Runs the Cloud Watchdog scanner"
  schedule_expression = var.scan_schedule
}

# 2. What: send the event to the scanner Lambda.
resource "aws_cloudwatch_event_target" "scanner" {
  rule = aws_cloudwatch_event_rule.daily_scan.name
  arn  = aws_lambda_function.scanner.arn
}

# 3. Allowed: let EventBridge invoke the Lambda.
# Without this the rule fires every day, the Lambda never runs, and nothing shows an error.
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeDailyScan"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}
