variable "kubeconfig_path" {
  type        = string
  description = "Path to an operator-approved kubeconfig."
  validation {
    condition     = length(trimspace(var.kubeconfig_path)) > 0
    error_message = "An explicit kubeconfig path is required."
  }
}

variable "kubeconfig_context" {
  type        = string
  description = "Operator-approved cluster context."
  validation {
    condition     = length(trimspace(var.kubeconfig_context)) > 0
    error_message = "An explicit kubeconfig context is required."
  }
}

variable "namespace" {
  type        = string
  description = "Dedicated namespace for the restricted Java workload."
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.namespace)) && var.namespace != "default" && !startswith(var.namespace, "kube-")
    error_message = "Provide a dedicated, non-system namespace."
  }
}

variable "pod_security_version" {
  type        = string
  description = "Pod Security Standards version supported by the target cluster (for example v1.31)."
  validation {
    condition     = can(regex("^v1\\.[0-9]{2}$", var.pod_security_version))
    error_message = "Provide an explicit Kubernetes minor version."
  }
}
