output "state_bucket" {
  description = "Put this in infra/envs/aws/backend.hcl and terraform.tfvars."
  value       = aws_s3_bucket.state.id
}

output "permissions_boundary_arn" {
  description = "Boundary the CI roles are created under."
  value       = aws_iam_policy.boundary.arn
}

output "state_kms_key_arn" {
  description = "CMK for the state bucket (CI roles need kms:Decrypt/GenerateDataKey on it)."
  value       = aws_kms_key.state.arn
}
