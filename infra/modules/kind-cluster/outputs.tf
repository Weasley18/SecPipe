output "name" {
  description = "Cluster name."
  value       = kind_cluster.this.name
}

output "kubeconfig_path" {
  description = "Path of the kubeconfig written by kind."
  value       = kind_cluster.this.kubeconfig_path
}

output "endpoint" {
  description = "API server endpoint."
  value       = kind_cluster.this.endpoint
}

output "audit_log_dir" {
  description = "Host directory with the API server audit log."
  value       = var.audit_log_dir
}
