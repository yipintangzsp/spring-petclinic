# Shared Security Manager

The public entry is `vars/securityManager.groovy`; tool selection is in `resources/security-manager/profiles.json`. The PetClinic adapter contains commands and credential IDs, not a copied Jenkinsfile. Generic tools live in `infra/security/manager/tool.mjs`; both routes archive independent reports and a unified `security-summary.json`.

Load the library at a reviewed fixed commit using Jenkins `library identifier: 'platform-security@<commit>', retriever: modernSCM([$class:'GitSCMSource', remote:'http'+'://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git', credentialsId:'gitlab-creds'])`.

Inside the existing node/checkout, call:

```groovy
securityManager(mode: 'audit', profile: 'python-api', project: 'my-api',
                runtimeRevision: '<same reviewed library commit>',
                sbomFile: 'build/application.cdx.json')
```

Use `mode: 'off'` to skip all optional scanners without removing code. Build/Test remains the caller's responsibility. Audit findings are WARN; operational errors still fail. Generic enforce blocks validated high-confidence findings; unconfigured targets are explicit `not_configured`, never fabricated zeroes and never sufficient for approved production promotion. Only PetClinic's separate signed approval contract can authorize its deployment. PetClinic adapter cannot be downgraded from enforce.

Profiles: java-web, python-api, container-service, infra-k8s, iac. Profile chooses tools; project settings enable target-specific modules. Image scanners require a fixed Harbor digest; Cosign needs the project's public key. Sonar needs project identity/command, ZAP explicit GET URLs, Kubescape a repository YAML path, and DefectDojo a dedicated engagement. Missing targets remain visible. No generic module copies Falco/Kyverno into a new project.

Execution uses the existing Jenkins agent, fixed tool manifests, isolated execution namespace and single platform-heavy Lease. It does not install tools, grant new RBAC or open new network paths. New project scan identities, registry access and approved DAST egress must be provisioned by platform owners. Java application and existing PetClinic gate semantics are unchanged; generic Python findings are review warnings, not a claim of full SAST coverage. The iac profile currently reuses repository YAML controls and existing script rules, not a comprehensive Terraform audit.

Generic reports go to Loki under `pipeline=security-manager`, with project/mode/profile. PetClinic's original summary, Dojo imports, Grafana and digest/promotion chain remain intact. Dojo uses native parsers and stable Test titles for deduplication. Do not put credentials in the configuration map: only existing Jenkins credential IDs.

DefectDojo domain route uses the existing Traefik Service plus selectorless Service/EndpointSlice to the Compose host's 18095 listener. Compose, data and backup port remain unchanged. Mac domain publication follows the existing Peach mDNS LaunchAgent method.

The PetClinic adapter uses an opt-in in-memory ZAP scratch backend: work tmpfs <=1 GiB, request 1536 MiB, limit 1792 MiB, within the existing 1800 MiB heavy-task allowance. The shared runtime defaults to disk for other modules. No VM resources, security rules, scan targets or persistent data change. The normal memory/PSI and disk stop guards remain active; all scratch is removed with the owned scanner Pod.
