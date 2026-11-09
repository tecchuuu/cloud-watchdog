# S3: one bucket for the JSON scan reports (reports/YYYY/MM/DD/<time>.json).
# The Report tab reads the last 30 of them for the history chart.

resource "aws_s3_bucket" "reports" {
  bucket        = "watchdog-reports-${local.account_id}" # bucket names are global, so add the account ID
  force_destroy = true                                   # let `tofu destroy` delete it even with reports inside
}

# Reports are private. Block every way of making this bucket public.
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
