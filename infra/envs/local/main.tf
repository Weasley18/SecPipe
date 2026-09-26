module "cluster" {
  source        = "../../modules/kind-cluster"
  name          = var.cluster_name
  workers       = var.workers
  audit_log_dir = var.audit_log_dir
}
