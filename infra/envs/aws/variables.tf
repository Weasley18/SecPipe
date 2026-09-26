variable "region" {
  description = "AWS region for every resource."
  type        = string
  default     = "eu-west-2"
}

variable "github_repository" {
  description = "owner/repo whose workflows may assume the CI roles."
  type        = string
  default     = "Weasley18/SecPipe"
}

variable "deploy_environment" {
  description = "GitHub environment (with a required reviewer) that gates terraform apply."
  type        = string
  default     = "aws-demo"
}

variable "state_bucket" {
  description = "Terraform state bucket created by infra/bootstrap."
  type        = string
}

variable "state_kms_key_arn" {
  description = "CMK encrypting the state bucket (bootstrap output state_kms_key_arn)."
  type        = string
}

variable "state_key" {
  description = "State object key (must match backend.hcl)."
  type        = string
  default     = "secpipe/aws/terraform.tfstate"
}

variable "reports_bucket_name" {
  description = "Globally unique name for the reports and SBOM bucket."
  type        = string
}

variable "owner" {
  description = "Owner tag applied to every resource."
  type        = string
  default     = "Weasley18"
}

variable "budget_emails" {
  description = "Addresses that receive budget alerts."
  type        = list(string)
}

variable "monthly_budget_usd" {
  description = "Monthly cost cap in USD (three CMKs cost about 3 USD/month)."
  type        = number
  default     = 10
}

variable "create_oidc_provider" {
  description = "Create the GitHub OIDC provider (false if the account already has one)."
  type        = bool
  default     = true
}

variable "existing_oidc_provider_arn" {
  description = "Existing GitHub OIDC provider ARN when create_oidc_provider is false."
  type        = string
  default     = null
}
