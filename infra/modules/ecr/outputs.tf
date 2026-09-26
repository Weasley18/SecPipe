output "repository_url" {
  description = "Registry URL to push to."
  value       = aws_ecr_repository.this.repository_url
}

output "repository_arn" {
  description = "Repository ARN (for IAM policies)."
  value       = aws_ecr_repository.this.arn
}

output "kms_key_arn" {
  description = "CMK encrypting the repository."
  value       = aws_kms_key.ecr.arn
}
