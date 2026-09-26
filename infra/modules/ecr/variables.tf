variable "name" {
  description = "Repository name."
  type        = string
  default     = "secnotes"
}

variable "untagged_expiry_days" {
  description = "Days after which untagged images (build leftovers) expire."
  type        = number
  default     = 7
}

variable "keep_tagged_images" {
  description = "How many tagged release images to keep."
  type        = number
  default     = 20
}

variable "push_principal_arns" {
  description = "IAM roles allowed to push (the GitHub OIDC publish role)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
