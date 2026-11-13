# PetClinic Helm Phase1 / Shadow Mode 验收报告

**Shadow 集成已验证；生产 Helm migration 未执行。** 本地提交 `c2338e00e07d5b028b1bb331bbc06885af433ee0`，未 push。生产 Jenkins仍 #270 SUCCESS，Argo仍使用V1，Security Runtime仍14/16。

独立 Jenkins job #5（关闭）与 #6（开启）SUCCESS。11资源/205字段等价；348项本地测试和断言通过，另8个真实离线受控stage负例均正确失败。首个专用构建#1的语法编译失败及修复证据完整保留。

验收限制：关闭模式是独立job的helper实跑+原生产pipeline逐字兼容证明，未重跑完整生产Security Manager。Kyverno/Kubescape引擎未执行，状态NOT_APPLICABLE；安全字段保留检查PASS。没有宣称新漏洞扫描或新增安全来源。

1. **current deployment inventory**

   {
     "currentGitOps": {
       "path": "k8s/production",
       "repoURL": "http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git",
       "targetRevision": "main"
     },
     "gitOpsRevision": "340ef4b8c74e3c2a5820da8d98b0f134283bb8d9",
     "productionJenkins": 270,
     "resourceScope": [
       {
         "apiVersion": "v1",
         "kind": "ConfigMap",
         "name": "petclinic-config",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "v1",
         "kind": "ConfigMap",
         "name": "petclinic-grafana-dashboard",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "v1",
         "kind": "ConfigMap",
         "name": "petclinic-metrics-dashboard",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "policy/v1",
         "kind": "PodDisruptionBudget",
         "name": "petclinic",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "monitoring.coreos.com/v1",
         "kind": "PrometheusRule",
         "name": "petclinic",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "v1",
         "kind": "ConfigMap",
         "name": "petclinic-release-analysis-dashboard",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "monitoring.coreos.com/v1",
         "kind": "ServiceMonitor",
         "name": "petclinic",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "v1",
         "kind": "ConfigMap",
         "name": "petclinic-v09-dashboard",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "apps/v1",
         "kind": "Deployment",
         "name": "petclinic",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "v1",
         "kind": "Service",
         "name": "petclinic",
         "namespace": "petclinic"
       },
       {
         "apiVersion": "networking.k8s.io/v1",
         "kind": "Ingress",
         "name": "petclinic",
         "namespace": "petclinic"
       }
     ],
     "deployment": {
       "apiVersion": "apps/v1",
       "kind": "Deployment",
       "metadata": {
         "name": "petclinic",
         "namespace": "petclinic",
         "annotations": {
           "gitops.zhanglab.io/cutover-test": "v1.27"
         }
       },
       "spec": {
         "replicas": 3,
         "minReadySeconds": 10,
         "progressDeadlineSeconds": 600,
         "revisionHistoryLimit": 5,
         "strategy": {
           "type": "RollingUpdate",
           "rollingUpdate": {
             "maxSurge": 0,
             "maxUnavailable": 1
           }
         },
         "selector": {
           "matchLabels": {
             "app": "petclinic"
           }
         },
         "template": {
           "metadata": {
             "labels": {
               "app": "petclinic"
             }
           },
           "spec": {
             "nodeSelector": {
               "kubernetes.io/os": "linux",
               "kubernetes.io/hostname": "devops"
             },
             "tolerations": [
               {
                 "key": "cloud",
                 "operator": "Equal",
                 "value": "true",
                 "effect": "NoSchedule"
               }
             ],
             "topologySpreadConstraints": [
               {
                 "maxSkew": 1,
                 "topologyKey": "kubernetes.io/hostname",
                 "whenUnsatisfiable": "ScheduleAnyway",
                 "labelSelector": {
                   "matchLabels": {
                     "app": "petclinic"
                   }
                 },
                 "matchLabelKeys": [
                   "pod-template-hash"
                 ]
               }
             ],
             "imagePullSecrets": [
               {
                 "name": "petclinic-harbor-pull"
               }
             ],
             "automountServiceAccountToken": false,
             "terminationGracePeriodSeconds": 45,
             "securityContext": {
               "runAsNonRoot": true,
               "runAsUser": 10001,
               "runAsGroup": 10001,
               "fsGroup": 10001,
               "seccompProfile": {
                 "type": "RuntimeDefault"
               }
             },
             "containers": [
               {
                 "name": "petclinic",
                 "image": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
                 "imagePullPolicy": "IfNotPresent",
                 "securityContext": {
                   "readOnlyRootFilesystem": true,
                   "allowPrivilegeEscalation": false,
                   "capabilities": {
                     "drop": [
                       "ALL"
                     ]
                   }
                 },
                 "ports": [
                   {
                     "name": "http",
                     "containerPort": 8080
                   }
                 ],
                 "env": [
                   {
                     "name": "SERVER_COMPRESSION_ENABLED",
                     "value": "true"
                   },
                   {
                     "name": "SERVER_COMPRESSION_MIN_RESPONSE_SIZE",
                     "value": "2KB"
                   },
                   {
                     "name": "SERVER_COMPRESSION_MIME_TYPES",
                     "value": "text/plain,application/openmetrics-text"
                   },
                   {
                     "name": "SPRING_SQL_INIT_MODE",
                     "value": "never"
                   },
                   {
                     "name": "SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE",
                     "value": "6"
                   },
                   {
                     "name": "SPRING_DATASOURCE_HIKARI_MINIMUM_IDLE",
                     "value": "2"
                   },
                   {
                     "name": "SERVER_SHUTDOWN",
                     "value": "graceful"
                   },
                   {
                     "name": "SPRING_LIFECYCLE_TIMEOUT_PER_SHUTDOWN_PHASE",
                     "value": "25s"
                   },
                   {
                     "name": "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE",
                     "value": "health,info,prometheus,metrics"
                   },
                   {
                     "name": "MANAGEMENT_OTLP_METRICS_EXPORT_ENABLED",
                     "value": "false"
                   },
                   {
                     "name": "MANAGEMENT_TRACING_EXPORT_OTLP_ENABLED",
                     "value": "true"
                   },
                   {
                     "name": "MANAGEMENT_OPENTELEMETRY_TRACING_EXPORT_OTLP_ENDPOINT",
                     "value": "http://otel-collector.monitoring.svc.cluster.local:4318/v1/traces"
                   },
                   {
                     "name": "MANAGEMENT_TRACING_SAMPLING_PROBABILITY",
                     "value": "1.0"
                   },
                   {
                     "name": "APPLICATION_VERSION",
                     "value": "0.10.0-ci-218"
                   },
                   {
                     "name": "BUILD_NUMBER",
                     "value": "218"
                   },
                   {
                     "name": "BUILD_GIT_COMMIT",
                     "value": "1fc223cb01a153b66e00ddbbff1b3b517a9784b1"
                   },
                   {
                     "name": "BUILD_TIME",
                     "value": "2026-10-27T04:59:35.090Z"
                   },
                   {
                     "name": "SPRING_PROFILES_ACTIVE",
                     "valueFrom": {
                       "configMapKeyRef": {
                         "name": "petclinic-config",
                         "key": "SPRING_PROFILES_ACTIVE"
                       }
                     }
                   },
                   {
                     "name": "POSTGRES_URL",
                     "valueFrom": {
                       "configMapKeyRef": {
                         "name": "petclinic-config",
                         "key": "POSTGRES_URL"
                       }
                     }
                   },
                   {
                     "name": "POSTGRES_USER",
                     "valueFrom": {
                       "secretKeyRef": {
                         "name": "petclinic-db",
                         "key": "POSTGRES_USER"
                       }
                     }
                   },
                   {
                     "name": "POSTGRES_PASS",
                     "valueFrom": {
                       "secretKeyRef": {
                         "name": "petclinic-db",
                         "key": "POSTGRES_PASS"
                       }
                     }
                   }
                 ],
                 "volumeMounts": [
                   {
                     "name": "runtime-tmp",
                     "mountPath": "/tmp"
                   },
                   {
                     "name": "platform-snapshot",
                     "mountPath": "/etc/petclinic-platform",
                     "readOnly": true
                   }
                 ],
                 "lifecycle": {
                   "preStop": {
                     "exec": {
                       "command": [
                         "/bin/sh",
                         "-c",
                         "sleep 5"
                       ]
                     }
                   }
                 },
                 "startupProbe": {
                   "httpGet": {
                     "path": "/actuator/health/liveness",
                     "port": "http"
                   },
                   "periodSeconds": 5,
                   "timeoutSeconds": 3,
                   "failureThreshold": 36
                 },
                 "readinessProbe": {
                   "httpGet": {
                     "path": "/actuator/health/readiness",
                     "port": "http"
                   },
                   "periodSeconds": 10,
                   "timeoutSeconds": 3,
                   "failureThreshold": 6
                 },
                 "livenessProbe": {
                   "httpGet": {
                     "path": "/actuator/health/liveness",
                     "port": "http"
                   },
                   "periodSeconds": 15,
                   "timeoutSeconds": 3,
                   "failureThreshold": 3
                 },
                 "resources": {
                   "requests": {
                     "cpu": "100m",
                     "memory": "512Mi"
                   },
                   "limits": {
                     "cpu": "500m",
                     "memory": "768Mi"
                   }
                 }
               }
             ],
             "volumes": [
               {
                 "name": "runtime-tmp",
                 "emptyDir": {
                   "sizeLimit": "128Mi"
                 }
               },
               {
                 "name": "platform-snapshot",
                 "configMap": {
                   "name": "petclinic-platform-snapshot",
                   "optional": true
                 }
               }
             ]
           }
         }
       }
     },
     "secretReferences": [
       {
         "name": "POSTGRES_USER",
         "valueFrom": {
           "secretKeyRef": {
             "name": "petclinic-db",
             "key": "POSTGRES_USER"
           }
         }
       },
       {
         "name": "POSTGRES_PASS",
         "valueFrom": {
           "secretKeyRef": {
             "name": "petclinic-db",
             "key": "POSTGRES_PASS"
           }
         }
       }
     ],
     "serviceAccount": "default (no explicit ServiceAccountName and no app-owned RBAC/SA in current GitOps)",
     "externalPrerequisites": [
       "petclinic-db Secret (never read)",
       "petclinic-harbor-pull Secret (never read)",
       "optional petclinic-platform-snapshot ConfigMap (externally owned)",
       "default ServiceAccount, token automount=false"
     ],
     "platformResourcesExcluded": [
       "platform-alertmanager Application",
       "spark-operator Application",
       "petclinic-harbor-alias Ingress in harbor namespace"
     ],
     "selectors": {
       "deployment": {
         "matchLabels": {
           "app": "petclinic"
         }
       },
       "podLabels": {
         "app": "petclinic"
       },
       "service": {
         "app": "petclinic"
       }
     },
     "promotionMechanism": "Signed approved-release + existing promotion/contract.mjs validation → promote.mjs updates plain-manifest image only → private GitLab main → Argo; rollback Git revert, never Helm rollback",
     "localManifestIsStale": true,
     "chartNotYetCreated": true
   }

   Evidence: `deployment-inventory.json`

2. **current GitOps path**

   {
     "source": {
       "path": "k8s/production",
       "repoURL": "http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git",
       "targetRevision": "main"
     },
     "revision": "340ef4b8c74e3c2a5820da8d98b0f134283bb8d9",
     "localOldYAMLNotBaseline": true
   }

   Evidence: `discovery.json`

3. **current Argo CD ownership**

   Existing Application petclinic owns V1 k8s/production.11 chart-scoped PetClinic resources preserved;3 platform resources stay V1. No source switch, takeover or simultaneous candidate Application.

   Evidence: `application-current.json`

4. **Helm version**

   {
     "version": "v3.22.1+gd6c1a0e",
     "actualLinuxARM64": true,
     "actualDarwinARM64": true,
     "AMD64": "Official archive/binary verified; not executed on AMD64 in this round"
   }

5. **Helm installation/tool strategy**

   {
     "lock": {
       "helmVersion": "v3.22.1",
       "officialRelease": "https://github.com/helm/helm/releases/tag/v3.22.1",
       "securitySupportEnd": "2027-02-10",
       "platforms": {
         "darwin-arm64": {
           "url": "https://get.helm.sh/helm-v3.22.1-darwin-arm64.tar.gz",
           "archiveSha256": "e73da8a0b0d5193774fdff17ce6319c7436bb22ee229b45fd64f3c40368c753a",
           "binarySha256": "b9fa0498b0eef0a2ff912c98fd6bbaba1b9e2c7a6e42063e406f1e4676272db9"
         },
         "linux-arm64": {
           "url": "https://get.helm.sh/helm-v3.22.1-linux-arm64.tar.gz",
           "archiveSha256": "4c29e286b279d170fa048ddfc3e4e83dcd069ca9c52102766ba672d7149e694d",
           "binarySha256": "2bd1b649ef89175bc0ae1e0fa7de7e0583a5b0401de9896b644b8acbcae1ba64"
         },
         "linux-amd64": {
           "url": "https://get.helm.sh/helm-v3.22.1-linux-amd64.tar.gz",
           "archiveSha256": "896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea",
           "binarySha256": "46aeab5e043f62d01f7c168823b392cabc1cea3807b67906296290483791be43"
         }
       }
     },
     "cache": "/var/jenkins_home/workspace/petclinic-helm-shadow-20261103/.tools/helm/v3.22.1/linux-arm64/helm",
     "systemHelmUnchanged": true,
     "strategy": "Workspace cache, archive+binary checksum verification, no global install, no Tiller. Existing network proxy failed; official archives fetched through read-only trusted host route, not changed proxy."
   }

6. **feature flag implementation**

   HELM_ENABLED=false by default. False helper returns before any step; true requires audit-only and performs shadow validation. Frozen Security Manager stages retain order; shadow uses current production digest, not candidate/approval. Local production entrypoint changes are not activated in pinned production Jenkins definition.

7. **chart structure**

   {
     "charts/petclinic/.helmignore": "3be9b7a5ae53c21fcae2b576c6e50e797ff32925e0670999bee5a6ccc9ce874b",
     "charts/petclinic/Chart.yaml": "214a03ea4694d0af78dd21f3575b1249125d05e529ffdd457a39c4baffa737e1",
     "charts/petclinic/files/observability.json": "cbf7576e36afe4f189ffc0736157229dc4dc1a307c7284e8b760dafdeee4c064",
     "charts/petclinic/templates/_helpers.tpl": "58e5130046e5282bb80ca1f28e9c570556de21f2efc7c5dada580b576e46c669",
     "charts/petclinic/templates/configmap.yaml": "51f80d63489c39c2d360671ef3a2d24025ce967def71d94d4832a1bbed4bb172",
     "charts/petclinic/templates/deployment.yaml": "aaad1b292cd6517a4a136a34a77c9ccb4f08ecba78191b29ef462da39ef95b6a",
     "charts/petclinic/templates/ingress.yaml": "77c44439010b920f74a60744d84d8bd7077fd5f45bb0fb03692477bb3c69263d",
     "charts/petclinic/templates/observability.yaml": "055f43e8e61fac24e6012ed7e0e73345033e737b7487aa2e830594b979082d32",
     "charts/petclinic/templates/pdb.yaml": "0d33524ef5002cf7cb1488f434f14a8550b56f7d90a307f84655219ce3b4c7fb",
     "charts/petclinic/templates/service.yaml": "9d747dc1384cbed649af144a44085949f945100921f7e9c2f5534436ac8e2d35",
     "charts/petclinic/values-prod.yaml": "91f1e6f1cb71fa2ccae34a6d992b5815d8cd1c3396dc96bcdbb29893445884b9",
     "charts/petclinic/values.schema.json": "39c3227bae8b863419e2c0b7cfac39e0c2c225a7433a5c958fe5503e3f88862b",
     "charts/petclinic/values.yaml": "1aed2a25429e783ccd17afdc9a63c9c355702c5ea6da1ddf3d6bbda72feca2a3"
   }

8. **Chart.yaml**

   apiVersion: v2
   name: petclinic
   description: PetClinic GitOps shadow representation; no production cutover
   type: application
   version: 0.1.0
   appVersion: "0.10.0"
   

9. **values model**

   All current Deployment/container/Service/Ingress/config/PDB/probe/resource/security/scheduling/env/volume/lifecycle inputs modeled; static6 observability objects retained byte-semantic identity in files/observability.json. JSON output is valid YAML; no extra YAML parser installation needed.

10. **prod values model**

   # SHADOW ONLY. Current deployed digest from GitOps revision 340ef4b8.
   # Future updates require signed approved-release evidence; appVersion/tags are not trust inputs.
   image:
     digest: sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137
   

11. **digest handling**

   {
     "renderedImage": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
     "appVersionTrustSource": false,
     "shadowUsesCurrentProductionOnly": true,
     "newDigestApproved": false,
     "approvedUpdaterRequiresSignedEvidence": true
   }

12. **Deployment template**

   {
     "path": "charts/petclinic/templates/deployment.yaml",
     "sha256": "aaad1b292cd6517a4a136a34a77c9ccb4f08ecba78191b29ef462da39ef95b6a",
     "equivalence": "VERIFIED"
   }

13. **Service template**

   {
     "path": "charts/petclinic/templates/service.yaml",
     "sha256": "9d747dc1384cbed649af144a44085949f945100921f7e9c2f5534436ac8e2d35",
     "equivalence": "VERIFIED"
   }

14. **Ingress template**

   {
     "path": "charts/petclinic/templates/ingress.yaml",
     "sha256": "77c44439010b920f74a60744d84d8bd7077fd5f45bb0fb03692477bb3c69263d",
     "equivalence": "VERIFIED"
   }

15. **ConfigMap handling**

   Primary config data and4 Grafana ConfigMaps preserved. No Secret object rendered. External optional platform-snapshot CM unchanged.

   Evidence: `field-diff-report.json`

16. **ServiceAccount/RBAC handling**

   Current app has no explicit SA/RBAC object; default SA with automountServiceAccountToken=false preserved. serviceAccount.create=false enforced; no invented SA/RBAC or new permissions. Secret references only.

17. **probes preservation**

   {
     "current": {
       "startupProbe": {
         "httpGet": {
           "path": "/actuator/health/liveness",
           "port": "http"
         },
         "periodSeconds": 5,
         "timeoutSeconds": 3,
         "failureThreshold": 36
       },
       "readinessProbe": {
         "httpGet": {
           "path": "/actuator/health/readiness",
           "port": "http"
         },
         "periodSeconds": 10,
         "timeoutSeconds": 3,
         "failureThreshold": 6
       },
       "livenessProbe": {
         "httpGet": {
           "path": "/actuator/health/liveness",
           "port": "http"
         },
         "periodSeconds": 15,
         "timeoutSeconds": 3,
         "failureThreshold": 3
       }
     },
     "comparison": "Exact equality VERIFIED"
   }

   Evidence: `field-diff-report.json`

18. **resources preservation**

   {
     "current": {
       "resources": {
         "requests": {
           "cpu": "100m",
           "memory": "512Mi"
         },
         "limits": {
           "cpu": "500m",
           "memory": "768Mi"
         }
       }
     },
     "comparison": "Exact equality VERIFIED"
   }

   Evidence: `field-diff-report.json`

19. **securityContext preservation**

   {
     "current": {
       "securityContext": {
         "readOnlyRootFilesystem": true,
         "allowPrivilegeEscalation": false,
         "capabilities": {
           "drop": [
             "ALL"
           ]
         }
       }
     },
     "comparison": "Exact equality VERIFIED"
   }

   Evidence: `field-diff-report.json`

20. **scheduling preservation**

   {
     "nodeSelector": {
       "kubernetes.io/os": "linux",
       "kubernetes.io/hostname": "devops"
     },
     "topology": [
       {
         "maxSkew": 1,
         "topologyKey": "kubernetes.io/hostname",
         "whenUnsatisfiable": "ScheduleAnyway",
         "labelSelector": {
           "matchLabels": {
             "app": "petclinic"
           }
         },
         "matchLabelKeys": [
           "pod-template-hash"
         ]
       }
     ],
     "tolerations": [
       {
         "key": "cloud",
         "operator": "Equal",
         "value": "true",
         "effect": "NoSchedule"
       }
     ],
     "architecturePinAdded": false,
     "affinityAbsentPreserved": true
   }

21. **observability preservation**

   Prometheus ServiceMonitor/PrometheusRule/selectors and dashboard data, app labels for Alloy/Loki, OTLP/Jaeger tracing env and PostgreSQL references preserved. No live observability redesign.

   Evidence: `field-diff-report.json`

22. **Helm lint result**

   PASS locally and dedicated Jenkins #6

   Evidence: `helm-lint.log`, `jenkins-artifacts-6/.helm-shadow/lint.log`

23. **Helm render result**

   PASS on DarwinARM64 and Jenkins LinuxARM64; exact render SHA equal

24. **rendered manifest hash**

   750a998e7fc32cb61c11fb2763ad870ee0b9f5c92895b8aae544f1a901c4d3f3

25. **semantic-equivalence result**

   {
     "status": "VERIFIED",
     "resources": 11,
     "fullLeafComparisons": 205,
     "driftCount": 0,
     "normalization": "object-key order/document formatting only; no meaningful field or runtime annotation ignored"
   }

   Evidence: `field-diff-report.json`

26. **Deployment comparison**

   {
     "kind": "Deployment",
     "status": "VERIFIED",
     "scope": "All spec/metadata fields, including selectors, ports, images, security, resources, probes, volumes, scheduling, env, grace/strategy; Ingress host/path/backend/TLS preserved"
   }

   Evidence: `field-diff-report.json`

27. **Service comparison**

   {
     "kind": "Service",
     "status": "VERIFIED",
     "scope": "All spec/metadata fields, including selectors, ports, images, security, resources, probes, volumes, scheduling, env, grace/strategy; Ingress host/path/backend/TLS preserved"
   }

   Evidence: `field-diff-report.json`

28. **Ingress comparison**

   {
     "kind": "Ingress",
     "status": "VERIFIED",
     "scope": "All spec/metadata fields, including selectors, ports, images, security, resources, probes, volumes, scheduling, env, grace/strategy; Ingress host/path/backend/TLS preserved"
   }

   Evidence: `field-diff-report.json`

29. **policy validation**

   {
     "status": "NOT_APPLICABLE",
     "preservationChecks": "PASS",
     "engineExecuted": false,
     "why": "Existing admission runner server-dry-runs cluster probes; frozen Kubescape orchestration requires outer Lease and mints read-only token. No existing pure offline rendered-manifest adapter exercised within no-mutation contract. Do not bypass resource/identity prerequisites or label static checks as real scanner PASS.",
     "futurePrerequisite": "A separately authorized supported offline/validation policy path before real cutover; existing production policy/Gates untouched"
   }

   Evidence: `policy-result.json`, `jenkins-artifacts-6/.helm-shadow/policy.json`

30. **digest guard**

   VERIFIED for shadow and future updater: missing/malformed/tag-only digest fails; candidate without approval cannot update; existing promotion contract reused. True shadow denies promotion actions. No new approval issued.

31. **GitOps update function**

   {
     "path": "infra/helm/update-image-digest.mjs",
     "behavior": "Validates digest and signed approval using existing pinned Cosign/public key; stale previous runtime rejected; only image.digest transformed; writes new candidate copy with wx and emits diff; no Git push",
     "tests": "Pure positive synthetic approval transformation + negative candidate/FAIL/stale/tag; signature invocation required before CLI output. No real new signed approval generated."
   }

32. **Argo CD Helm candidate**

   {
     "path": "infra/argocd/petclinic-helm-candidate.yaml",
     "status": "NOT_ACTIVE / VALIDATION_ONLY",
     "sourcePath": "charts/petclinic",
     "values": [
       "values-prod.yaml"
     ],
     "repoRevisionDestinationSyncPolicyPreserved": true,
     "applied": false,
     "caution": "Inherited automated sync policy; never apply candidate alongside V1. Future chart must first exist in correct GitOps revision under separate approved change."
   }

33. **production Application mutation count**

   0

34. **direct deployment command scan**

   VERIFIED active+shadow CI entrypoints; negative guard tests reject forbidden commands. Scope excludes unchanged approved scanner diagnostic implementations.

   Evidence: `helm-tests.log`

35. **HELM_ENABLED=false compatibility**

   {
     "status": "VERIFIED",
     "job": "petclinic-helm-shadow-20261103",
     "build": 5,
     "result": "SUCCESS",
     "runtimeDisabledHelperExecuted": true,
     "allHelmStagesSkipped": true,
     "pipelineAssertions": 13,
     "originalProductionPipelineWithoutHelmBlocksByteIdentical": true,
     "scopeLimit": "No full production Security Manager pipeline rerun, to preserve production #270 and blocked14/16 roadmap. This is dedicated runtime disabled-helper + exact source-compatibility proof."
   }

   Evidence: `jenkins-build-5.json`, `jenkins-build-5.log`

36. **HELM_ENABLED=true validation build**

   {
     "job": "petclinic-helm-shadow-20261103",
     "build": 6,
     "result": "SUCCESS",
     "reviewManifestSha256": "3080ab4b431e7314882e64be2f2110563ecd9e378db02ccb597925126dfa675d",
     "allHelmStagesExecuted": true,
     "productionPushOrDeploy": false
   }

   Evidence: `jenkins-build-6.json`, `jenkins-build-6.log`

37. **negative tests**

   {
     "controlledOfflineStageExecutions": 8,
     "allCorrectNonzero": true,
     "fixtures": [
       "missing digest",
       "malformed digest",
       "tag image",
       "Deployment selector mismatch",
       "Service selector mismatch",
       "invalid template",
       "privileged container",
       "missing request"
     ],
     "tempRemoved": true,
     "productionFilesModified": false,
     "firstJenkinsFailure": "#1 failed Declarative compile due inline when/steps formatting, fixed and linter verified; failure log retained, not counted as a controlled negative sample"
   }

   Evidence: `negative-stage-fixtures.json`, `jenkins-build-1.log`

38. **chart tests**

   {
     "tests": 43,
     "pass": 43,
     "fail": 0
   }

   Evidence: `helm-tests.log`

39. **current pipeline tests**

   {
     "Regression": 147,
     "newPipelineCompatibilityAndProhibitionAssertions": 13,
     "JenkinsNativeLinter": "Both entrypoints successfully validated",
     "productionFullPipelineRerun": false
   }

   Evidence: `jenkins-native-lint.json`

40. **runtime tests**

   {
     "tests": 143,
     "pass": 143,
     "fail": 0
   }

41. **Policy core**

   {
     "tests": 5,
     "pass": 5,
     "fail": 0
   }

42. **contract tests**

   {
     "tests": 10,
     "pass": 10,
     "fail": 0
   }

43. **Regression147/147**

   {
     "tests": 147,
     "pass": 147,
     "fail": 0
   }

44. **source/hash preservation**

   {
     "status": "VERIFIED_WITH_EXPLICIT_ADDITIVE_CI_DELTA",
     "existingImplementationFilesUnchanged": 77,
     "newEpochToolingFilesUnchanged": 9,
     "oldUniqueGateSourceFiles": 229,
     "byteIdenticalGateSourceFiles": 228,
     "authorizedDeltas": [
       {
         "path": "Jenkinsfile.security-audit",
         "before": "e6e7c1b8f838e42e8bc9b3aa35e731515e2e05feb300bd1833d64aa921c54ed2",
         "after": "6179859f70c1d6fec2560621ec1ae71dba20514de4ff430d84b7d60a1c319b3c",
         "authorizedChange": "Additive Helm parameters/preconditions/validation/archive blocks only",
         "frozenGateTextRestoredSha256": "e6e7c1b8f838e42e8bc9b3aa35e731515e2e05feb300bd1833d64aa921c54ed2"
       }
     ],
     "compatibilityCorpusCountUnchanged": 2202,
     "priorEvidenceFilesUnchanged": 1284,
     "priorSeals": [
       {
         "path": "evidence/2026-11-03/runtime-checkpoint-epoch-v2/evidence-sha256.json",
         "sha256": "52209072295e2e590333214f9585d0fda67987afa149210232c97e531992d0f9",
         "files": 86
       },
       {
         "path": "evidence/2026-11-03/trivy-guard-experiment-design/evidence-sha256.json",
         "sha256": "bc60c85686bf6c8d2a9367dadbf10a41fc33865976c36b86037ea124fea51e8a",
         "files": 40
       },
       {
         "path": "evidence/2026-11-03/trivy-guard-dependency-boundary-review/evidence-sha256.json",
         "sha256": "1941a09be4807004a3be168e42cd44611984ba172bf85b33dc8d928cd171662d",
         "files": 44
       },
       {
         "path": "evidence/2026-11-03/trivy-resource-feasibility-audit/evidence-sha256.json",
         "sha256": "9a15a3edac9071e31bc3d4ca94d218c47a283bb5e723ef7717aab5e4e2148b0d",
         "files": 49
       }
     ],
     "existingCheckpointRebased": false,
     "currentEpochContinuityClaimed": false,
     "note": "Old historical acceptance/evidence untouched. A replay against this newer working-tree source must report the authorized Jenkinsfile raw hash change; no old integrity manifest was rewritten."
   }

   Evidence: `source-preservation.json`

45. **production Jenkins state**

   {
     "job": "petclinic-ci",
     "latestBuild": 270,
     "result": "SUCCESS",
     "SCMBranchUnchanged": [
       "9a78cc89f22fa98fb1ffcc43e2ae279299471793"
     ],
     "newHelmCodeNotActivatedInProductionJob": true
   }

   Evidence: `live-jenkins-final.json`

46. **production digest**

   core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137

47. **Argo CD production state**

   {
     "source": {
       "path": "k8s/production",
       "repoURL": "http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git",
       "targetRevision": "main"
     },
     "revision": "340ef4b8c74e3c2a5820da8d98b0f134283bb8d9",
     "sourceAndSpecUnchanged": true,
     "candidateAbsent": true,
     "sync": "Synced",
     "health": "Healthy"
   }

   Evidence: `production-protection.json`, `final-production-verification.json`

48. **nodes state**

   devops / aliyun-worker / ucloud-worker Ready

   Evidence: `node-lease-postflight.json`

49. **PetClinic state**

   3/3 Ready;3 Ready Endpoint; Deployment/Service/Ingress UID and spec unchanged

   Evidence: `live-protected-final.json`

50. **HTTP result**

   200

51. **release count**

   0

52. **rollout count**

   0

53. **HELM_TOOLING_INTEGRATION**

   VERIFIED

54. **HELM_CHART**

   VERIFIED

55. **HELM_RENDER_EQUIVALENCE**

   VERIFIED

56. **HELM_DIGEST_GUARD**

   VERIFIED

57. **HELM_GITOPS_UPDATE_FUNCTION**

   VERIFIED

58. **ARGOCD_HELM_CANDIDATE**

   VERIFIED

59. **HELM_ENABLED_FALSE_COMPATIBILITY**

   VERIFIED

60. **HELM_VALIDATION_MODE**

   VERIFIED

61. **HELM_PRODUCTION_CUTOVER**

   NOT_PERFORMED

62. **exact remaining Helm blockers**

   {
     "phase1Shadow": "No render/tooling/structural blocker remains within declared shadow scope.",
     "limits": [
       "No real Kyverno/Kubescape engine run; policy preservation only, NOT_APPLICABLE engine status",
       "No full production Gate pipeline rerun or production job activation; off-mode evidence is explicitly scoped",
       "AMD64 Helm archive verified but actual AMD64 execution not performed",
       "Chart/candidate code committed locally only, no GitOps push or source activation"
     ],
     "futureCutoverBlockedBy": [
       "Security runtime14/16 / Trivy resource audit closed and blocked / Dojo dependency",
       "Future signed approved digest and policy checks",
       "Ownership separation for two platform Applications and Harbor alias",
       "Explicit cutover authorization, current baseline revalidation and rollback verification"
     ]
   }

63. **exact future cutover prerequisites**

   Follow docs/helm/FUTURE-CUTOVER.md: satisfy security roadmap, freeze current state, real approved digest + policy verification, exact render diff, resolve platform ownership, publish reviewed GitOps source separately, update existing Application only in approved window, Argo owns reconciliation, monitor HTTP/endpoints/metrics/logs/traces, Git revert/V1 source restore on failure. None executed.

64. **exact next permitted action**

   STOP. Keep V1 active and chart/candidate inactive. Local commit c2338e00e07d5b028b1bb331bbc06885af433ee0 saved on feature branch, not pushed. No production Helm install/upgrade/rollback, kubectl workload mutation, GitOps push, new digest promotion or SummaryV2. Resource audit remains CLOSED until material change.

## Final verdicts

```text
HELM_TOOLING_INTEGRATION=VERIFIED
HELM_CHART=VERIFIED
HELM_LINT=PASS
HELM_RENDER=PASS
HELM_RENDER_EQUIVALENCE=VERIFIED
HELM_POLICY_VALIDATION=NOT_APPLICABLE
HELM_DIGEST_GUARD=VERIFIED
HELM_GITOPS_UPDATE_FUNCTION=VERIFIED
ARGOCD_HELM_CANDIDATE=VERIFIED
DIRECT_DEPLOYMENT_PROHIBITION=VERIFIED
HELM_ENABLED_FALSE_COMPATIBILITY=VERIFIED
HELM_VALIDATION_MODE=VERIFIED
HELM_PRODUCTION_CUTOVER=NOT_PERFORMED
PRODUCTION_HELM_DEPLOYMENT=NOT_ACTIVE
TRIVY_RUNTIME_FACT_CAPTURE=INCOMPLETE
DEFECTDOJO_RUNTIME_FACT_CAPTURE=INCOMPLETE
FINAL_WIRED_CAPABILITY=14/16
REAL_RUNTIME_FACT_CAPTURE=INCOMPLETE
REAL_POLICY_OWNER=INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME=INCOMPLETE
SUMMARY_V2_MIGRATION=INCOMPLETE
RELEASE_COUNT=0
ROLLOUT_COUNT=0
```

STOP。
