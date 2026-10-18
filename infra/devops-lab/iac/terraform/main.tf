terraform {
  required_version = ">= 1.7.0, < 2.0.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.38.0"
    }
  }
}

provider "kubernetes" {
  config_path = "/etc/rancher/k3s/k3s.yaml"
}

variable "namespace_name" {
  type = string
  validation {
    condition     = var.namespace_name == "tf-devops-lab"
    error_message = "This exercise can manage only tf-devops-lab."
  }
}

variable "scenario" {
  type = string
  validation {
    condition     = var.scenario == "petclinic-devops-study"
    error_message = "Unexpected learning scenario."
  }
}

variable "config_revision" {
  type = string
  validation {
    condition     = contains(["v1", "v2"], var.config_revision)
    error_message = "Only v1 or v2 configuration is allowed."
  }
}

resource "kubernetes_namespace_v1" "lab" {
  metadata {
    name = var.namespace_name
    labels = {
      "app.kubernetes.io/part-of"    = "devops-learning"
      "petclinic.devops.local/owner" = "terraform-iac-lab"
    }
  }
}

resource "kubernetes_resource_quota_v1" "budget" {
  metadata {
    name      = "lab-budget"
    namespace = kubernetes_namespace_v1.lab.metadata[0].name
  }
  spec {
    hard = {
      "pods"                   = "0"
      "persistentvolumeclaims" = "0"
      "secrets"                = "0"
      "services"               = "0"
      "configmaps"             = "4"
      "requests.storage"       = "0"
    }
  }
}

resource "kubernetes_config_map_v1" "environment" {
  metadata {
    name      = "environment-manifest"
    namespace = kubernetes_namespace_v1.lab.metadata[0].name
  }
  data = {
    scenario        = var.scenario
    config_revision = var.config_revision
    managed_by      = "terraform"
  }
}

output "namespace_uid" {
  value = kubernetes_namespace_v1.lab.metadata[0].uid
}
