# Local kind cluster: 1 control plane + N workers, Calico CNI (so NetworkPolicy
# is enforced) and API server audit logging (so `kubectl exec`, RBAC changes and
# pod creation are recorded for the SIEM-lite stack).

locals {
  audit_patch   = <<-EOT
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml
        audit-log-path: /var/log/kubernetes/audit/audit.log
        audit-log-maxage: "7"
        audit-log-maxbackup: "3"
        audit-log-maxsize: "50"
      extraVolumes:
        - name: audit-policies
          hostPath: /etc/kubernetes/policies
          mountPath: /etc/kubernetes/policies
          readOnly: true
          pathType: DirectoryOrCreate
        - name: audit-logs
          hostPath: /var/log/kubernetes/audit
          mountPath: /var/log/kubernetes/audit
          readOnly: false
          pathType: DirectoryOrCreate
  EOT
  ingress_patch = <<-EOT
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  EOT
}

resource "kind_cluster" "this" {
  name           = var.name
  node_image     = var.node_image
  wait_for_ready = false # nodes stay NotReady until Calico is installed below

  kind_config {
    kind        = "Cluster"
    api_version = "kind.x-k8s.io/v1alpha4"

    networking {
      disable_default_cni = true
      pod_subnet          = var.pod_subnet
    }

    node {
      role                   = "control-plane"
      kubeadm_config_patches = [local.audit_patch, local.ingress_patch]

      extra_mounts {
        host_path      = abspath("${path.module}/audit-policy.yaml")
        container_path = "/etc/kubernetes/policies/audit-policy.yaml"
        read_only      = true
      }

      extra_mounts {
        host_path      = var.audit_log_dir
        container_path = "/var/log/kubernetes/audit"
      }

      extra_port_mappings {
        container_port = 80
        host_port      = var.ingress_http_port
        listen_address = "127.0.0.1"
      }

      extra_port_mappings {
        container_port = 443
        host_port      = var.ingress_https_port
        listen_address = "127.0.0.1"
      }
    }

    dynamic "node" {
      for_each = range(var.workers)
      content {
        role = "worker"
      }
    }
  }
}

# Calico enforces NetworkPolicy; kindnet does not.
resource "terraform_data" "calico" {
  triggers_replace = [kind_cluster.this.id, var.calico_version]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      KUBECONFIG     = kind_cluster.this.kubeconfig_path
      CALICO_VERSION = var.calico_version
    }
    command = <<-EOT
      set -euo pipefail
      kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/$${CALICO_VERSION}/manifests/calico.yaml"
      kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
      kubectl wait --for=condition=Ready nodes --all --timeout=300s
    EOT
  }
}
