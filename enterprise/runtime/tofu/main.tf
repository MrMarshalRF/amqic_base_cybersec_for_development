terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.36"
    }
  }
}

provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kubeconfig_context
}

resource "kubernetes_namespace_v1" "workloads" {
  metadata {
    name = var.namespace
    labels = {
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = var.pod_security_version
      "pod-security.kubernetes.io/audit"           = "restricted"
      "pod-security.kubernetes.io/audit-version"   = var.pod_security_version
      "pod-security.kubernetes.io/warn"            = "restricted"
      "pod-security.kubernetes.io/warn-version"    = var.pod_security_version
    }
  }
}

resource "kubernetes_network_policy_v1" "default_deny" {
  metadata {
    namespace = kubernetes_namespace_v1.workloads.metadata[0].name
    name      = "default-deny"
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}
