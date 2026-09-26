variable "role_name" {
  description = "IAM role name (prefixed secpipe- so the terraform role can manage it)."
  type        = string

  validation {
    condition     = startswith(var.role_name, "secpipe-")
    error_message = "Role names must start with secpipe-."
  }
}

variable "github_repository" {
  description = "owner/repo allowed to assume the role, e.g. Weasley18/SecPipe."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "Use owner/repo without wildcards."
  }
}

variable "allowed_subjects" {
  description = <<-EOT
    Exact OIDC `sub` claims that may assume the role, e.g.
    repo:Weasley18/SecPipe:ref:refs/heads/main or
    repo:Weasley18/SecPipe:environment:aws-demo. Wildcards are rejected: a
    pattern such as repo:owner/* lets any branch, fork or repository of that
    owner assume the role.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.allowed_subjects) > 0 && alltrue([for s in var.allowed_subjects : !strcontains(s, "*") && !strcontains(s, "?")])
    error_message = "allowed_subjects must be exact subjects without wildcards."
  }

  validation {
    condition     = alltrue([for s in var.allowed_subjects : startswith(s, "repo:${var.github_repository}:")])
    error_message = "Every subject must belong to var.github_repository."
  }
}

variable "policy_json" {
  description = "Least-privilege inline policy for the role."
  type        = string
}

variable "create_oidc_provider" {
  description = "Create the account's GitHub OIDC provider (only once per account)."
  type        = bool
  default     = true
}

variable "oidc_provider_arn" {
  description = "Existing GitHub OIDC provider ARN when create_oidc_provider is false."
  type        = string
  default     = null
}

variable "permissions_boundary_arn" {
  description = "Permissions boundary for the role (the bootstrap's secpipe-ci-boundary)."
  type        = string
  default     = null
}

variable "max_session_duration" {
  description = "Maximum session length in seconds."
  type        = number
  default     = 3600
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
