output "plan_role_arn" {
  description = "Repository variable AWS_PLAN_ROLE_ARN."
  value       = module.plan_role.role_arn
}

output "apply_role_arn" {
  description = "Environment (aws-demo) variable AWS_APPLY_ROLE_ARN."
  value       = module.apply_role.role_arn
}

output "publish_role_arn" {
  description = "Repository variable AWS_PUBLISH_ROLE_ARN."
  value       = module.publish_role.role_arn
}

output "ecr_repository_url" {
  description = "Push target for the AWS profile."
  value       = module.ecr.repository_url
}

output "reports_bucket" {
  description = "Bucket that keeps gate reports and SBOMs."
  value       = module.reports_bucket.bucket_name
}
