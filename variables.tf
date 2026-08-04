# terraform/baselines/aws/variables.tf
# ★ TYPE YOUR CODE HERE

variable "aws_region" {
  type        = string
  description = "AWS region for all baseline resources."
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Short project identifier used in resource names and tags."
  default     = "cgep-lab"
}
