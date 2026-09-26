variable "cluster_name" {
  description = "kind cluster name."
  type        = string
  default     = "secpipe"
}

variable "workers" {
  description = "Worker nodes (the spec's layout is 1 control plane + 2 workers)."
  type        = number
  default     = 2
}

variable "audit_log_dir" {
  description = "Host directory receiving the API server audit log."
  type        = string
  default     = "/tmp/secpipe-audit"
}
