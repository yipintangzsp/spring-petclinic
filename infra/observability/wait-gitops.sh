#!/bin/sh
set -eu
TARGET_GIT_SHA=${1:?target Git revision required}
: "${K8S_IMAGE:?target image required}"
deadline=$(($(date +%s) + ${GITOPS_WAIT_SECONDS:-900}))
sync_ok=0

for attempt in $(seq 1 "${GITOPS_MAX_ATTEMPTS:-180}"); do
    # Read Argo fields from one object. Argo's comparison cache can briefly say
    # Synced before its sync operation has applied the Deployment.
    state=$(kubectl --request-timeout=15s -n argocd get application petclinic \
        -o jsonpath='{.status.sync.status}{" "}{.status.health.status}{" "}{.status.sync.revision}' 2>/dev/null || true)
    sync=$(printf '%s' "$state" | cut -d ' ' -f1)
    health=$(printf '%s' "$state" | cut -d ' ' -f2)
    revision=$(printf '%s' "$state" | cut -d ' ' -f3)
    image=$(kubectl --request-timeout=15s -n petclinic get deployment petclinic \
        -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)
    echo "ARGO_CHECK=${attempt} SYNC=${sync} HEALTH=${health} REVISION=${revision} LIVE_IMAGE=${image}"
    if [ "$sync" = Synced ] && [ "$revision" = "$TARGET_GIT_SHA" ] && [ "$image" = "$K8S_IMAGE" ]; then
        sync_ok=1
        break
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then break; fi
    sleep "${GITOPS_POLL_SECONDS:-5}"
done

if [ "$sync_ok" != 1 ]; then
    echo "ERROR: Argo and live Deployment did not converge to ${TARGET_GIT_SHA} / ${K8S_IMAGE}"
    exit 1
fi
echo "ARGOCD_DEPLOYMENT=OK"
