resource "aws_s3_bucket" "trail" {
  bucket        = "cgep-lab-cloudtrail-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail.json
}

resource "aws_cloudtrail" "mgmt" {
  name                          = "cgep-lab-mgmt"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}

resource "aws_securityhub_account" "this" {}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

"Effect": "Deny", "Action": "config:*"

AccessDeniedException: User ... is not authorized to perform: config:PutConfigurationRecorder
on resource ... with an explicit deny in a service control policy

eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
terraform init
terraform apply -auto-approve

aws cloudtrail get-trail-status --name cgep-lab-mgmt --region us-east-1 \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'
# Expect IsLogging: true

aws securityhub describe-hub --region us-east-1 --query HubArn
# Expect arn:aws:securityhub:us-east-1:ACCOUNT:hub/default

aws securityhub get-findings --region us-east-1 --max-results 5 \
  --query 'Findings[?Severity.Label==`CRITICAL`].{Title:Title,GeneratorId:GeneratorId}' \
  --output json

[
  {
    "Title": "AWS Config should be enabled and use the service-linked role for resource recording",
    "GeneratorId": "security-control/Config.1"
  }
]

mkdir -p evidence/lab-5-2
aws securityhub get-findings --region us-east-1 --max-results 50 \
  > evidence/lab-5-2/security-hub-findings.json

wc -c evidence/lab-5-2/security-hub-findings.json
# 25KB or so for a small account


