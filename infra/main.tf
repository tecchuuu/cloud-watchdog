# Shared lookups used by the other files.
# Each service has its own file: s3.tf, dynamodb.tf, ...
# OpenTofu reads every .tf file in this folder as one configuration.

# Who am I? Gives the 12-digit account ID, used to make bucket names unique.
data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Learner Lab can't create IAM roles, so both Lambdas use the lab's LabRole.
  # Built from the account ID instead of looked up, so no IAM read is needed.
  lab_role_arn = "arn:aws:iam::${local.account_id}:role/LabRole"
}
