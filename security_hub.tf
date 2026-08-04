# terraform/baselines/aws/security_hub.tf
# ★ TYPE YOUR CODE HERE — Security Hub (RA-5, SI-4)

# Enable Security Hub in the account.
# If it's already enabled: terraform import aws_securityhub_account.this <ACCOUNT_ID>
resource "aws_securityhub_account" "this" {}

# NIST 800-53 Rev 5 standard — ~300 controls evaluated
resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# AWS Foundational Security Best Practices standard
resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}
