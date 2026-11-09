# DynamoDB: two tables, both on-demand (pay per request, nothing when idle).

# Latest state of every finding. One row per problem.
# finding_id = <check>#<region>#<resource_id>, e.g. unused_eip#us-east-1#eipalloc-0abc
resource "aws_dynamodb_table" "findings" {
  name         = "watchdog_findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S" # string
  }
}

# Audit log: who did Fix / Delete / Ignore, when, and the hash chain.
# Every entry has pk = "LOG" and a running number seq (1, 2, 3...),
# so reading the table in seq order replays the log from the start.
resource "aws_dynamodb_table" "actions" {
  name         = "watchdog_actions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "seq"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "seq"
    type = "N" # number
  }
}
