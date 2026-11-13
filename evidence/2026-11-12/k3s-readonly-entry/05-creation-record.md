# K3s Readonly Entry - Creation Record (2026-11-12)

## Objects created (admin via sudo kubectl, one-time setup only)
- Namespace: platform-ops (new; chosen over kube-system for clean separation/revocation)
- ServiceAccount: platform-ops/platform-readonly (automountServiceAccountToken: false)
- ClusterRole: platform-readonly (verbs get/list/watch ONLY)
- ClusterRoleBinding: platform-readonly -> SA platform-ops/platform-readonly
Manifest: 01-manifest.yaml (byte-identical to applied file). Apply output: 02-apply-output.txt (all four objects "created").

## Permission matrix (all verbs = get/list/watch only; NO write verbs anywhere; NO secrets)
- core "": nodes, pods, services, namespaces, events, configmaps
- apps: deployments, daemonsets, statefulsets, replicasets
- events.k8s.io: events
- argoproj.io: applications, applicationsets, appprojects, rollouts (read-only status visibility)
- kyverno.io: clusterpolicies, policies
- policies.kyverno.io: validatingpolicies, mutatingpolicies, generatingpolicies, imagevalidatingpolicies, deletingpolicies
- wgpolicyk8s.io: clusterpolicyreports, policyreports
- reports.kyverno.io: clusterephemeralreports, ephemeralreports
Excluded deliberately: secrets (any group), pods/log, exec/attach, leases/tokens, any create/update/patch/delete verb.

## Token + kubeconfig
- Token: TokenRequest API, SA platform-ops/platform-readonly, duration 8760h (issued 2026-11-12 22:18 CST, expires ~2027-11-12). Token value is NOT recorded in any file/report; the temporary token file on devops was shredded after embedding.
- Kubeconfig: devops:/home/zhang/.kube/platform-readonly.yaml, mode 600, owner zhang:zhang, 2088 bytes. Server https://127.0.0.1:6443 (intended for use on the devops host itself).
- Renewal: re-run kubectl -n platform-ops create token platform-readonly --duration=8760h with admin kubeconfig and rebuild the kubeconfig the same way.

## Creation commands (as executed on devops, 2026-11-12 22:18 CST)
1. Write manifest to /tmp/platform-readonly.yaml (copy kept as 01-manifest.yaml; also on devops ~/platform-readonly-evidence/)
2. sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/platform-readonly.yaml
3. sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml -n platform-ops create token platform-readonly --duration=8760h  (to a 600 temp file, shredded after use)
4. kubectl config set-cluster/set-credentials/set-context/use-context into ~/.kube/platform-readonly.yaml with embedded CA; chmod 600

## Verification (raw output: 03-verification.txt)
- POSITIVE: get nodes OK (3/3 Ready); get deploy -A OK; petclinic pods OK; Argo CD applications OK (14, Synced/Healthy); Kyverno clusterpolicies OK (3, Ready True)
- NEGATIVE: get secrets -> Forbidden; label node -> Forbidden (cannot patch nodes); create configmap -> Forbidden
- can-i: get nodes yes / list pods yes / get configmaps yes / get secrets no / create pods no / delete deployments no

## Cluster snapshot
See 04-cluster-snapshot.txt (taken 2026-11-12T22:18:45+08:00 through the NEW readonly kubeconfig).

## Revocation (NOT executed this round)
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete clusterrolebinding platform-readonly
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete clusterrole platform-readonly
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete sa -n platform-ops platform-readonly
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete namespace platform-ops
rm /home/zhang/.kube/platform-readonly.yaml
(Deleting the SA immediately invalidates the issued token.)

## Scope compliance
No existing resource modified; no workload touched; Security Manager production state untouched (NOT_ACTIVE, unrelated to this item).
Raw evidence also retained on devops: ~/platform-readonly-evidence/ (01-04, byte-identical).
