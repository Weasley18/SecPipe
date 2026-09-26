output "role_arn" {
  description = "ARN to put in the workflow's aws-actions/configure-aws-credentials step."
  value       = aws_iam_role.this.arn
}

output "oidc_provider_arn" {
  description = "GitHub OIDC provider ARN (reuse it for further roles)."
  value       = local.oidc_provider_arn
}
