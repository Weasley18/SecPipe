output "kubeconfig_path" {
  description = "export KUBECONFIG=$(terraform output -raw kubeconfig_path)"
  value       = module.cluster.kubeconfig_path
}

output "cluster_name" {
  description = "kind cluster name (for kind load docker-image --name)."
  value       = module.cluster.name
}

output "audit_log_dir" {
  description = "Where the API server audit log lands on the host."
  value       = module.cluster.audit_log_dir
}
