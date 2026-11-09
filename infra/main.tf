# Shared lookups used by the other files.
# Each service has its own file: s3.tf, dynamodb.tf, ...
# OpenTofu reads every .tf file in this folder as one configuration.

# Who am I? Gives the 12-digit account ID, used to make bucket names unique.
data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}
