# S3: one bucket for the JSON scan reports (reports/YYYY/MM/DD/<time>.json).
# The Report tab reads the last 30 of them for the history chart.
#
# Why not the normal aws_s3_bucket resource?
# After creating a bucket, that resource always reads back its "object lock"
# setting, and Learner Lab's service control policy denies that one call
# (s3:GetBucketObjectLockConfiguration -> 403). So OpenTofu creates and deletes
# the bucket by running the AWS CLI instead. `tofu apply` / `tofu destroy`
# still handle it; the trade-off is that OpenTofu can't notice changes made
# to the bucket by hand (it never reads the bucket back).

locals {
  reports_bucket = "watchdog-reports-${local.account_id}" # bucket names are global, so add the account ID
}

resource "terraform_data" "reports_bucket" {
  input = local.reports_bucket # changing the name = delete the old bucket, create a new one

  # On create: make the bucket, block all public access, tag it.
  # (us-east-1 only: other regions also need --create-bucket-configuration.)
  # default_tags don't reach CLI-made resources, so the tags are set here.
  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    environment = { BUCKET = self.input }
    command     = <<-EOT
      set -e
      aws s3api create-bucket --bucket "$BUCKET" --region us-east-1 > /dev/null
      aws s3api put-public-access-block --bucket "$BUCKET" \
        --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
      aws s3api put-bucket-tagging --bucket "$BUCKET" \
        --tagging 'TagSet=[{Key=managed-by,Value=watchdog},{Key=project,Value=cloud-watchdog}]'
      echo "Created private bucket $BUCKET"
    EOT
  }

  # On destroy: delete every report, then the bucket.
  provisioner "local-exec" {
    when        = destroy
    interpreter = ["bash", "-c"]
    environment = { BUCKET = self.input }
    command     = <<-EOT
      if aws s3api head-bucket --bucket "$BUCKET" 2> /dev/null; then
        aws s3 rb "s3://$BUCKET" --force
      else
        echo "Bucket $BUCKET already gone"
      fi
    EOT
  }
}
