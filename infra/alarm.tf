# CloudWatch alarm: who watches the Watchdog?
# If the scanner fails even once in a day (a check errored, a timeout, a bug),
# email the same SNS topic. scanner.py fails on purpose after saving when any
# check had an error, so this alarm fires.

resource "aws_cloudwatch_metric_alarm" "scanner_errors" {
  alarm_name        = "watchdog-scanner-errors"
  alarm_description = "The Cloud Watchdog scanner failed. Check its logs: /aws/lambda/watchdog-scanner"

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  dimensions = {
    FunctionName = aws_lambda_function.scanner.function_name
  }

  statistic           = "Sum"
  period              = 86400 # one day, in seconds
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching" # no runs today = not an error

  alarm_actions = [aws_sns_topic.alerts.arn]
}
