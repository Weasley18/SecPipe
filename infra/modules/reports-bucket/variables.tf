variable "bucket_name" {
  description = "Globally unique bucket name for scan reports and SBOMs."
  type        = string
}

variable "owner" {
  description = "Value of the mandatory owner tag (enforced by CKV2_SECPIPE_1)."
  type        = string
}

variable "retention_days" {
  description = "Days before reports and noncurrent versions expire."
  type        = number
  default     = 90

  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 365
    error_message = "Keep reports between 1 and 365 days."
  }
}

variable "writer_role_arns" {
  description = "Roles allowed to write reports (the CI publish role)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
