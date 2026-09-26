variable "name" {
  description = "kind cluster name."
  type        = string
  default     = "secpipe"
}

variable "node_image" {
  description = "kindest/node image, pinned by digest (the kind v0.33 default)."
  type        = string
  default     = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
}

variable "workers" {
  description = "Number of worker nodes."
  type        = number
  default     = 2

  validation {
    condition     = var.workers >= 1 && var.workers <= 4
    error_message = "Use between 1 and 4 workers on a laptop."
  }
}

variable "pod_subnet" {
  description = "Pod CIDR; must match the Calico IP pool."
  type        = string
  default     = "192.168.0.0/16"
}

variable "calico_version" {
  description = "Calico release whose manifest is applied (the default CNI does not enforce NetworkPolicy)."
  type        = string
  default     = "v3.32.2"
}

variable "audit_log_dir" {
  description = "Host directory that receives the API server audit log (tailed by Grafana Alloy)."
  type        = string
  default     = "/tmp/secpipe-audit"
}

variable "ingress_http_port" {
  description = "Host port mapped to the ingress controller's port 80."
  type        = number
  default     = 8080
}

variable "ingress_https_port" {
  description = "Host port mapped to the ingress controller's port 443."
  type        = number
  default     = 8443
}
