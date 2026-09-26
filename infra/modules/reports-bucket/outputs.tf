output "bucket_name" {
  description = "Reports bucket name."
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "Reports bucket ARN (for IAM policies)."
  value       = aws_s3_bucket.this.arn
}

output "kms_key_arn" {
  description = "CMK encrypting the bucket (writers need kms:GenerateDataKey on it)."
  value       = aws_kms_key.reports.arn
}
