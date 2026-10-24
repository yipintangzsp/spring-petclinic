# Terraform / Ansible isolated environment lab

This exercise reuses the installed Terraform 1.17.0 and Ansible Core 2.16.3 on the existing server. The Kubernetes provider is pinned to 2.38.0 and its checked-in lock file. No new always-on service is installed.

Ansible renders and validates deterministic public inputs. Terraform manages exactly three objects: namespace `tf-devops-lab`, a ResourceQuota preventing Pods/PVCs/Secrets/Services, and one ConfigMap. It uses the existing local K3s administrator kubeconfig, so this is not a demonstration of least-privilege provisioning or public-cloud IaC. Do not copy credentials into this directory.

Run source from an approved private GitLab revision after the full Jenkins release passes. A guarded controller must acquire the existing heavy Lease only once, preserve Jenkins quiet state, and run tools in a bounded transient systemd service (MemoryMax768M, CPUQuota100%, TasksMax128, RuntimeMaxSec600). Terraform's independent local state lock does not request the Kubernetes heavy Lease again.

Use a new root-owned mode0700 work directory below `/opt/petclinic-observability/labs/iac-<run-id>`. Copy `terraform/main.tf` and the committed lock file there. Keep state, plans, and logs private and outside Git. Set `TF_IN_AUTOMATION=1`, `TF_INPUT=0`, `TF_CLI_ARGS=-no-color`.

```sh
ansible-playbook -i ansible/inventory.ini ansible/configure.yaml -e iac_workdir=<private-workdir> --check --diff
ansible-playbook -i ansible/inventory.ini ansible/configure.yaml -e iac_workdir=<private-workdir>
# Repeat: changed=0; invalid namespace must fail before altering the config.
terraform -chdir=<private-workdir> init -input=false -lockfile=readonly
terraform -chdir=<private-workdir> validate
terraform -chdir=<private-workdir> plan -input=false -out=create.tfplan
# Inspect the saved plan: exactly three creates, no outside resources.
terraform -chdir=<private-workdir> apply -input=false create.tfplan
terraform -chdir=<private-workdir> plan -input=false -detailed-exitcode
```

Expected repeated plan exit code is0. Change only the owned ConfigMap's config_revision to `out-of-band`: detailed plan must return2 and propose exactly one in-place update. Apply that saved repair plan, verify v1 restored, then require plan exit0.

Before destroy, compare namespace UID against Terraform output and verify ownership, the exact state resource list, and absence of Pods/PVCs/Secrets or foreign objects. Only then create and inspect a saved destroy plan for these three objects. Preserve all local state/history/logs after resource removal. Abort cleanup if ownership or contents change; never delete an existing business namespace, force namespace finalizers, or prune PVCs to finish the exercise.

Acceptance must record preview without mutation, first apply, second-run idempotency, invalid-parameter rejection with unchanged file SHA256, actual drift detection/repair, resource removal, final empty state and a repeated destroy plan with exit0 and Jenkins/Lease recovery. An installation/version check alone is not acceptance.

Official references: https://registry.terraform.io/providers/hashicorp/kubernetes/2.38.0/docs ; https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/template_module.html

A normal plan after destroy intentionally proposes creation again. The final zero-change assertion is a **destroy** plan against empty state. The controller invokes Terraform with explicit flags and uses the server CLI; the Mac CLI is an older1.5.7 and is not used to validate/apply this1.7+ exercise. Provider2.38.0 signature/checksums were retrieved and locked by the server Terraform CLI from the official Registry for LinuxARM64.

## Jenkins plan gate (2026-10-24)

The existing petclinic-ci pipeline runs `Terraform Plan` after tests and before packaging, under its already-owned heavy Lease. It installs the pinned Linux ARM64 CLI into the persistent Jenkins tools directory and verifies both archive and binary SHA256. It uses the existing Pod service account for provider authentication; the original server controller retains its default kubeconfig path. No new credentials or permissions are created. The existing Jenkins service account is privileged; this does not demonstrate least-privilege provisioning.

The stage runs fmt, init with the committed read-only provider lock, validate and a saved plan. It rejects an existing lab namespace, modifications/deletions/replacements, any additional resource, changed namespace/owner, or a quota allowing Pods/PVCs/Secrets/Services. It requires exactly the original namespace, quota and ConfigMap creates. It does not apply Kubernetes resources. The sanitized result is archived as target/platform/terraform.json; the full saved plan and logs remain private under JENKINS_HOME/terraform-runs/ci-<build>-<nonce> with owner-only access, outside source control. Existing pipeline timeout and concurrency guards apply, with an additional eight-minute stage limit.

After a successful full source release, use the existing run.py controller for the real disposable lifecycle and drift-repair acceptance. Do not apply an old CI preview to a changed cluster: generate and inspect a fresh plan with that controller. This is a local-state learning workflow, not a shared remote backend or automatic production provisioning.

Full integration accepted by Jenkins #189 at source f161884266dfdad49e6704c4b651f169d031b4b0; the subsequent Terraform1.17.0 lifecycle, idempotency, invalid input, drift repair, scoped teardown and Jenkins/Lease restoration passed. See docs/TERRAFORM-20261024.md.
