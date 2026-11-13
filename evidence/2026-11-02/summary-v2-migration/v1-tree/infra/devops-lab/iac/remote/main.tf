terraform {
  required_version = "= 1.17.0"
  backend "kubernetes" {
    namespace     = "terraform-state"
    secret_suffix = "petclinic-remote-v1"
    labels = {
      "petclinic.devops.local/owner" = "terraform-remote-lab"
    }
  }
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.38.0"
    }
  }
}

# Both backend and provider receive only the short-lived scoped identity via environment.
provider "kubernetes" {}

variable "coordination_probe" {
  type    = bool
  default = false
}

resource "kubernetes_config_map_v1" "environment" {
  metadata {
    name      = "environment-manifest"
    namespace = "tf-remote-lab"
    labels = {
      "petclinic.devops.local/owner" = "terraform-remote-lab"
    }
  }
  data = {
    scenario        = "petclinic-devops-study"
    config_revision = "v1"
    managed_by      = "terraform"
  }
}

# This state-only probe holds a real apply lock while client B attempts a plan.
# It creates no infrastructure or files; it is removed before the final plan.
resource "terraform_data" "coordination_probe" {
  count = var.coordination_probe ? 1 : 0
  input = "bounded-state-lock-probe"
  provisioner "local-exec" {
    command = "sleep 10"
  }
}

output "config_map_uid" {
  value = kubernetes_config_map_v1.environment.metadata[0].uid
}
