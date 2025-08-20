#!/bin/bash

# Prompt for base path
read -p "Enter base path for PCD dump (default: /tmp): " BASEPATH
BASEPATH=${BASEPATH:-/tmp}

# Step 1: Create dump directory
DUMP_DIR="${BASEPATH}/pcddump-$(date +%F_%H-%M-%S)"
mkdir -p "$DUMP_DIR"

echo "Dump directory: $DUMP_DIR"

# Step 2: Collect namespaces info
kubectl get ns >  "${DUMP_DIR}/get-namespaces.txt"
kubectl get ns -o wide >  "${DUMP_DIR}/get-owide-namespaces.txt"
kubectl get ns --show-labels > "${DUMP_DIR}/get-show-labels-namespaces.txt"
kubectl describe namespace > "${DUMP_DIR}/namespaces-describe.txt"
kubectl get namespace -o yaml > "${DUMP_DIR}/namespaces.yaml"

# Step 3: Collect cluster-wide resources (example)
CLUSTER_RESOURCES=(
    persistentvolumes
    storageclasses
    ingressclasses
    clusterrolebindings
    clusterroles
    nodes
    csidrivers
    csinodes
    csistoragecapacities
    customresourcedefinitions
    priorityclasses
    runtimeclasses
    volumeattachments
    mutatingwebhookconfigurations
    validatingwebhookconfigurations
)

for resource in "${CLUSTER_RESOURCES[@]}"; do
    kubectl get "$resource" > "${DUMP_DIR}/get-${resource}.txt" 2>/dev/null
    kubectl get "$resource" -o wide > "${DUMP_DIR}/get-owide-${resource}.txt" 2>/dev/null
    kubectl get "$resource" --show-labels > "${DUMP_DIR}/get-show-labels-${resource}.txt" 2>/dev/null
    kubectl describe "$resource" > "${DUMP_DIR}/${resource}-describe.txt" 2>/dev/null
    kubectl get "$resource" -o yaml > "${DUMP_DIR}/${resource}.yaml" 2>/dev/null
done

# Step 4: Collect events
kubectl get events -A > "${DUMP_DIR}/get-all-events.txt" 2>/dev/null

# Step 5: Collect metrics
mkdir -p "${DUMP_DIR}/metrics"
kubectl top nodes > "${DUMP_DIR}/metrics/nodes-usage.txt" 2>/dev/null
kubectl top pods -A > "${DUMP_DIR}/metrics/pods-usage.txt" 2>/dev/null

# Step 6: Collect version info
kubectl version > "${DUMP_DIR}/cluster-version.txt" 2>/dev/null

# Step 7: Integrity checksums
find "${DUMP_DIR}" -type f -exec sha256sum {} \; > "${DUMP_DIR}/integrity.checksums"

echo "✅ Cluster dump completed at $DUMP_DIR"
