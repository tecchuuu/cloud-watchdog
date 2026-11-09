# SNS: one topic that emails alert_email.
# Used by the scanner (new issues, Monday reminder) and the CloudWatch alarm
# (scanner errors). In a real team this would be a mailing list.

resource "aws_sns_topic" "alerts" {
  name = "watchdog-alerts"
}

# AWS sends a "Confirm subscription" email first. Nothing arrives until you click it.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
