#!/usr/bin/env python3
import yaml
import os
import argparse
import sys
import datetime
import re

VERSION = "2.6.3"

NON_NS_RESOURCES = [
    "persistentvolumes", "storageclasses", "ingressclasses",
    "clusterrolebindings", "clusterroles", "nodes", "csidrivers",
    "csinodes", "csistoragecapacities", "customresourcedefinitions",
    "priorityclasses", "runtimeclasses", "volumeattachments",
    "mutatingwebhookconfigurations", "validatingwebhookconfigurations"
]

NS_RESOURCES = [
    "pods", "deployments", "statefulsets", "daemonsets", "replicasets",
    "services", "events", "jobs", "cronjobs", "secrets", "configmaps",
    "endpoints", "persistentvolumeclaims", "resourcequotas", "networkpolicies",
    "poddisruptionbudgets", "rolebindings", "roles", "ingresses"
]

SHORTNAMES = {
    "po": "pods", "pod": "pods", "pods": "pods",
    "deploy": "deployments", "deployment": "deployments", "deployments": "deployments",
    "sts": "statefulsets", "statefulset": "statefulsets", "statefulsets": "statefulsets",
    "ds": "daemonsets", "daemonset": "daemonsets", "daemonsets": "daemonsets",
    "rs": "replicasets", "replicaset": "replicasets", "replicasets": "replicasets",
    "svc": "services", "service": "services", "services": "services",
    "ev": "events", "event": "events", "events": "events",
    "cm": "configmaps", "configmap": "configmaps", "configmaps": "configmaps",
    "secret": "secrets", "secrets": "secrets",
    "ep": "endpoints", "endpoints": "endpoints",
    "pvc": "persistentvolumeclaims", "persistentvolumeclaim": "persistentvolumeclaims", "persistentvolumeclaims": "persistentvolumeclaims",
    "quota": "resourcequotas", "resourcequota": "resourcequotas", "resourcequotas": "resourcequotas",
    "netpol": "networkpolicies", "networkpolicy": "networkpolicies", "networkpolicies": "networkpolicies",
    "pdb": "poddisruptionbudgets", "poddisruptionbudget": "poddisruptionbudgets", "poddisruptionbudgets": "poddisruptionbudgets",
    "rolebinding": "rolebindings", "rolebindings": "rolebindings",
    "role": "roles", "roles": "roles",
    "ing": "ingresses", "ingress": "ingresses", "ingresses": "ingresses",
    "job": "jobs", "jobs": "jobs",
    "cj": "cronjobs", "cronjob": "cronjobs", "cronjobs": "cronjobs",
    "no": "nodes", "node": "nodes", "nodes": "nodes",
    "pv": "persistentvolumes", "persistentvolume": "persistentvolumes", "persistentvolumes": "persistentvolumes",
    "sc": "storageclasses", "storageclass": "storageclasses", "storageclasses": "storageclasses",
    "crd": "customresourcedefinitions", "customresourcedefinition": "customresourcedefinitions", "customresourcedefinitions": "customresourcedefinitions",
    "clusterrole": "clusterroles", "clusterroles": "clusterroles",
    "clusterrolebinding": "clusterrolebindings", "clusterrolebindings": "clusterrolebindings",
    "ns": "namespaces", "namespace": "namespaces", "namespaces": "namespaces",
    "all": "all"
}
for _r in NS_RESOURCES + NON_NS_RESOURCES + ["namespaces"]:
    SHORTNAMES[_r] = _r

ALL_RESOURCES = NON_NS_RESOURCES + NS_RESOURCES + ["namespaces"]
RESOURCE_FILE_MAP = {r: "%s.yaml" % r for r in ALL_RESOURCES}
BASEPATH_FILE = ".basepath"

def parse_resource_file(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding="utf-8", errors="replace") as f:
        try:
            data = yaml.safe_load(f)
        except Exception as e:
            print("Error reading %s: %s" % (file_path, e), file=sys.stderr)
            return []
    if not data:
        return []
    if isinstance(data, dict) and 'items' in data:
        return data['items']
    elif isinstance(data, list):
        return data
    elif isinstance(data, dict):
        return [data]
    return []

def parse_kubectl_table_file(file_path):
    if not os.path.exists(file_path):
        return [], []
    with open(file_path, 'r', encoding="utf-8", errors="replace") as f:
        lines = [l.rstrip('\n') for l in f if l.strip()]
    if not lines:
        return [], []
    headers = [h.strip() for h in re.split(r'\s{2,}|\t', lines[0])]
    rows = []
    for line in lines[1:]:
        row = [c.strip() for c in re.split(r'\s{2,}|\t', line)]
        while len(row) < len(headers):
            row.append('')
        rows.append(row)
    return headers, rows

def truncate_cell(cell, maxlen):
    cell = str(cell)
    if len(cell) > maxlen:
        return cell[:maxlen-3] + "..."
    return cell

def print_kubectl_table(headers, rows, col_truncate=None):
    if col_truncate is None:
        col_truncate = {}
    preview_rows = []
    for row in rows:
        preview_row = []
        for i, cell in enumerate(row):
            if i in col_truncate:
                preview_row.append(truncate_cell(cell, col_truncate[i]))
            else:
                preview_row.append(str(cell))
        preview_rows.append(preview_row)
    col_widths = [len(str(h)) for h in headers]
    for row in preview_rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    header_line = " ".join(str(h).ljust(col_widths[i]) for i, h in enumerate(headers))
    print(header_line)
    for row in preview_rows:
        row_line = " ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
        print(row_line)

def get_basepath():
    # 1. Try env variable 'basepath' (lowercase, as requested)
    env_basepath = os.environ.get("basepath")
    if env_basepath and os.path.isdir(env_basepath):
        return os.path.abspath(env_basepath)
    # 2. Try env variable 'CLUSTER_DUMP_BASEPATH' (legacy)
    env_basepath_legacy = os.environ.get("CLUSTER_DUMP_BASEPATH")
    if env_basepath_legacy and os.path.isdir(env_basepath_legacy):
        return os.path.abspath(env_basepath_legacy)
    # 3. Try .basepath file
    if os.path.exists(BASEPATH_FILE):
        with open(BASEPATH_FILE, "r") as f:
            path = f.read().strip()
            if path and os.path.isdir(path):
                return os.path.abspath(path)
    # 4. Prompt user
    path = input("Enter absolute path to the PCD-dump directory - Example: /home/user/tmp/pcdump : ").strip()
    if not path or not os.path.isdir(path):
        print("Error: Valid basepath must be specified.", file=sys.stderr)
        sys.exit(1)
    with open(BASEPATH_FILE, "w") as f:
        f.write(path)
    return os.path.abspath(path)

def load_namespaced_resources(basepath, resource, namespace=None, all_namespaces=False):
    items = []
    if all_namespaces:
        for ns_dir in os.listdir(basepath):
            ns_path = os.path.join(basepath, ns_dir)
            if os.path.isdir(ns_path):
                file_path = os.path.join(ns_path, "%s.yaml" % resource)
                if os.path.exists(file_path):
                    for item in parse_resource_file(file_path):
                        if "namespace" not in item.get("metadata", {}):
                            item["metadata"]["namespace"] = ns_dir
                        items.append(item)
    elif namespace:
        ns_dir = os.path.join(basepath, namespace)
        file_path = os.path.join(ns_dir, "%s.yaml" % resource)
        if os.path.exists(file_path):
            for item in parse_resource_file(file_path):
                if "namespace" not in item.get("metadata", {}):
                    item["metadata"]["namespace"] = namespace
                items.append(item)
    else:
        ns_dir = os.path.join(basepath, "default")
        file_path = os.path.join(ns_dir, "%s.yaml" % resource)
        if os.path.exists(file_path):
            for item in parse_resource_file(file_path):
                if "namespace" not in item.get("metadata", {}):
                    item["metadata"]["namespace"] = "default"
                items.append(item)
    return items

def get_all_resources(basepath, namespace=None, all_namespaces=False):
    all_types = ["pods", "services", "deployments", "replicasets", "statefulsets", "daemonsets", "jobs", "cronjobs"]
    results = {}
    for r in all_types:
        if all_namespaces:
            items = load_namespaced_resources(basepath, r, None, all_namespaces=True)
        elif namespace:
            items = load_namespaced_resources(basepath, r, namespace)
        else:
            items = load_namespaced_resources(basepath, r, None, all_namespaces=False)
        results[r] = items
    return results

def print_resource_table(basepath, resource, items, namespace=None, owidemode=False, resource_name=None, show_namespace_col=False, show_labels=False, all_namespaces=False, filter_names=None):
    def print_table_from_txt(file_path, filter_names=None):
        headers, rows = parse_kubectl_table_file(file_path)
        if not headers:
            print(f"No data found in {file_path}")
            return
        if filter_names:
            name_idx = None
            for i, h in enumerate(headers):
                if h.lower() == "name":
                    name_idx = i
                    break
            if name_idx is not None:
                rows = [r for r in rows if r[name_idx] in filter_names]
        print_kubectl_table(headers, rows)
    if all_namespaces:
        all_headers = None
        all_rows = []
        for ns_dir in sorted(os.listdir(basepath)):
            ns_path = os.path.join(basepath, ns_dir)
            if not os.path.isdir(ns_path):
                continue
            if owidemode:
                file_path = os.path.join(ns_path, f"get-owide-{resource}.txt")
            elif show_labels:
                file_path = os.path.join(ns_path, f"get-show-labels-{resource}.txt")
            else:
                file_path = os.path.join(ns_path, f"get-{resource}.txt")
            headers, rows = parse_kubectl_table_file(file_path)
            if headers and rows:
                if filter_names:
                    name_idx = None
                    for i, h in enumerate(headers):
                        if h.lower() == "name":
                            name_idx = i
                            break
                    if name_idx is not None:
                        rows = [r for r in rows if r[name_idx] in filter_names]
                if all_headers is None:
                    all_headers = headers
                ns_col_present = any('namespace' in h.lower() for h in headers)
                if not ns_col_present:
                    all_headers = ["NAMESPACE"] + headers
                    for r in rows:
                        all_rows.append([ns_dir] + r)
                else:
                    all_rows.extend(rows)
        if not all_headers:
            print(f"No data found for {resource} in any namespace")
            return
        print_kubectl_table(all_headers, all_rows)
        return
    ns_dir = os.path.join(basepath, namespace) if namespace else os.path.join(basepath, "default")
    if owidemode:
        file_path = os.path.join(ns_dir, f"get-owide-{resource}.txt")
    elif show_labels:
        file_path = os.path.join(ns_dir, f"get-show-labels-{resource}.txt")
    else:
        file_path = os.path.join(ns_dir, f"get-{resource}.txt")
    print_table_from_txt(file_path, filter_names=filter_names)

def print_yaml(items, filter_names=None):
    if not items:
        print("No resources found.")
        return
    if filter_names:
        items = [item for item in items if item.get("metadata", {}).get("name", "") in filter_names]
    print(yaml.safe_dump(items, sort_keys=False))

def print_api_resources():
    kind_map = {
        "pods": "Pod", "deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet",
        "replicasets": "ReplicaSet", "services": "Service", "events": "Event", "jobs": "Job", "cronjobs": "CronJob",
        "secrets": "Secret", "configmaps": "ConfigMap", "endpoints": "Endpoints", "persistentvolumeclaims": "PersistentVolumeClaim",
        "resourcequotas": "ResourceQuota", "networkpolicies": "NetworkPolicy", "poddisruptionbudgets": "PodDisruptionBudget",
        "rolebindings": "RoleBinding", "roles": "Role", "ingresses": "Ingress",
        "persistentvolumes": "PersistentVolume", "storageclasses": "StorageClass", "ingressclasses": "IngressClass",
        "clusterrolebindings": "ClusterRoleBinding", "clusterroles": "ClusterRole", "nodes": "Node", "csidrivers": "CSIDriver",
        "csinodes": "CSINode", "csistoragecapacities": "CSIStorageCapacity", "customresourcedefinitions": "CustomResourceDefinition",
        "priorityclasses": "PriorityClass", "runtimeclasses": "RuntimeClass", "volumeattachments": "VolumeAttachment",
        "mutatingwebhookconfigurations": "MutatingWebhookConfiguration", "validatingwebhookconfigurations": "ValidatingWebhookConfiguration",
        "namespaces": "Namespace"
    }
    apigroup_map = {
        "deployments": "apps", "statefulsets": "apps", "daemonsets": "apps", "replicasets": "apps",
        "jobs": "batch", "cronjobs": "batch", "networkpolicies": "networking.k8s.io", "ingresses": "networking.k8s.io",
        "ingressclasses": "networking.k8s.io", "storageclasses": "storage.k8s.io", "persistentvolumes": "",
        "persistentvolumeclaims": "", "configmaps": "", "secrets": "", "services": "", "pods": "",
        "events": "", "endpoints": "", "resourcequotas": "", "poddisruptionbudgets": "policy",
        "roles": "rbac.authorization.k8s.io", "rolebindings": "rbac.authorization.k8s.io",
        "clusterroles": "rbac.authorization.k8s.io", "clusterrolebindings": "rbac.authorization.k8s.io",
        "customresourcedefinitions": "apiextensions.k8s.io", "priorityclasses": "scheduling.k8s.io",
        "runtimeclasses": "node.k8s.io", "volumeattachments": "storage.k8s.io",
        "mutatingwebhookconfigurations": "admissionregistration.k8s.io",
        "validatingwebhookconfigurations": "admissionregistration.k8s.io",
        "csidrivers": "storage.k8s.io", "csinodes": "storage.k8s.io",
        "csistoragecapacities": "storage.k8s.io", "namespaces": "",
        "nodes": ""
    }
    sn_map = {}
    for sn, full in SHORTNAMES.items():
        sn_map.setdefault(full, []).append(sn)
    for full in sn_map:
        sn_map[full] = [sn for sn in sn_map[full] if sn != full]
    rows = []
    for r in NS_RESOURCES + NON_NS_RESOURCES + ["namespaces"]:
        name = r
        shortnames = ",".join(sorted(set(sn_map.get(r, []))))
        apigroup = apigroup_map.get(r, "")
        namespaced = "true" if r in NS_RESOURCES else "false"
        kind = kind_map.get(r, r.title().replace("s", "", 1))
        rows.append([name, shortnames, apigroup, namespaced, kind])
    headers = ["NAME", "SHORTNAMES", "APIGROUP", "NAMESPACED", "KIND"]
    print_kubectl_table(headers, rows)

def print_all_table(results, all_namespaces=False, namespace=None):
    out_rows = []
    out_headers = None
    for rtype, items in results.items():
        for item in items:
            meta = item.get("metadata", {})
            name = meta.get("name", "")
            ns = meta.get("namespace", namespace if namespace else "")
            status = item.get("status", {})
            ready = ""
            restarts = ""
            age = ""
            if rtype == "pods":
                ready = str(status.get("containerStatuses", [{}])[0].get("ready", ""))
                if isinstance(status.get("containerStatuses", []), list):
                    ready_count = sum(1 for cs in status.get("containerStatuses", []) if cs.get("ready"))
                    total_count = len(status.get("containerStatuses", []))
                    ready = f"{ready_count}/{total_count}"
                restarts = str(sum(cs.get("restartCount", 0) for cs in status.get("containerStatuses", [])))
                if "creationTimestamp" in meta:
                    try:
                        dt = datetime.datetime.strptime(meta["creationTimestamp"], "%Y-%m-%dT%H:%M:%SZ")
                        now = datetime.datetime.now(datetime.timezone.utc)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=datetime.timezone.utc)
                        delta = now - dt
                        age = "%dd" % (delta.days)
                    except Exception:
                        age = ""
                pod_status = status.get("phase", "")
            else:
                pod_status = ""
                if "creationTimestamp" in meta:
                    try:
                        dt = datetime.datetime.strptime(meta["creationTimestamp"], "%Y-%m-%dT%H:%M:%SZ")
                        now = datetime.datetime.now(datetime.timezone.utc)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=datetime.timezone.utc)
                        delta = now - dt
                        age = "%dd" % (delta.days)
                    except Exception:
                        age = ""
            prefix = f"{rtype[:-1] if rtype.endswith('s') and rtype != 'jobs' else rtype}/{name}"
            row = []
            if all_namespaces:
                row.append(ns)
            row.append(prefix)
            if rtype == "pods":
                row += [ready, pod_status, restarts, age]
            else:
                row += ["", pod_status, "", age]
            out_rows.append(row)
    if all_namespaces:
        out_headers = ["NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE"]
    else:
        out_headers = ["NAME", "READY", "STATUS", "RESTARTS", "AGE"]
    print_kubectl_table(out_headers, out_rows)

def print_describe_for_resource(basepath, resource, namespace, name=None):
    if resource in NS_RESOURCES and namespace:
        describe_path = os.path.join(basepath, namespace, "%s-describe.txt" % resource)
    else:
        describe_path = os.path.join(basepath, "%s-describe.txt" % resource)
    if not os.path.exists(describe_path):
        print("Describe file not found for %s." % resource)
        sys.exit(1)
    with open(describe_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    if name:
        pattern = re.compile(r"(^|\n)Name:\s*%s(\s|\n|$)" % re.escape(name))
        match = pattern.search(content)
        if match:
            start = match.start(0)
            next_match = re.compile(r"(^|\n)Name:\s*\S+").search(content, match.end())
            end = next_match.start(0) if next_match else len(content)
            print(content[start:end].lstrip("\n"))
            return
        loose_pattern = r"Name:\s*%s" % re.escape(name)
        idx = content.find(loose_pattern)
        if idx != -1:
            next_match = re.compile(r"(^|\n)Name:\s*\S+").search(content, idx + len(loose_pattern))
            end = next_match.start(0) if next_match else len(content)
            print(content[idx:end].lstrip("\n"))
            return
        print("Resource %s not found in describe file." % (name,))
    else:
        items = load_namespaced_resources(basepath, resource, namespace)
        names = [item.get("metadata", {}).get("name", "") for item in items if item.get("metadata", {}).get("name", "")]
        if not names:
            print("No %s found in namespace %s." % (resource, namespace))
            return
        for nm in names:
            print("="*80)
            print("Describe for %s '%s':" % (resource, nm))
            print("="*80)
            print_describe_for_resource(basepath, resource, namespace, nm)
            print()

def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes resource viewer",
        usage="%(prog)s <command> [<args>]\n\n"
              "Commands:\n"
              "  get         Get resources\n"
              "  describe    Describe a resource\n"
              "  logs        Show pod logs\n"
              "  top         Show resource usage metrics\n"
              "  api-resources List resource types (like kubectl api-resources)\n"
              "\nRun '%(prog)s <command> --help' for more info on a command."
    )
    parser.add_argument('--version', action='version', version=VERSION)
    subparsers = parser.add_subparsers(dest="command")

    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("resource")
    get_parser.add_argument("resource_names", nargs="*", help="Name(s) of the resource(s) (optional, multiple allowed)")
    get_parser.add_argument("-n", "--namespace", help="Namespace to filter by (if applicable)")
    get_parser.add_argument("-A", "--all-namespaces", action="store_true", help="List across all namespaces")
    get_parser.add_argument("-b", "--basepath", help="Base path to cluster-dump directory")
    get_parser.add_argument("-oyaml", "--oyaml", action="store_true", help="Output full yaml")
    get_parser.add_argument("-owide", "--owide", action="store_true", help="Wide output (extra columns)")
    get_parser.add_argument("--show-labels", action="store_true", help="Show labels column")

    describe_parser = subparsers.add_parser("describe")
    describe_parser.add_argument("resource")
    describe_parser.add_argument("name", nargs="?", help="Name of the resource (optional)")
    describe_parser.add_argument("-n", "--namespace", help="Namespace of the resource")
    describe_parser.add_argument("-b", "--basepath", help="Base path to cluster-dump directory")

    logs_parser = subparsers.add_parser("logs")
    logs_parser.add_argument("pod_name")
    logs_parser.add_argument("-n", "--namespace", help="Namespace of the pod (required)")
    logs_parser.add_argument("-b", "--basepath", help="Base path to cluster-dump directory")
    logs_parser.add_argument("--previous", action="store_true", help="Show previous terminated container logs if present")

    top_parser = subparsers.add_parser("top")
    top_parser.add_argument("resource", choices=["pods", "nodes"])
    top_parser.add_argument("-n", "--namespace", help="Namespace filter for pods")
    top_parser.add_argument("-b", "--basepath", help="Base path to cluster-dump directory")

    api_resources_parser = subparsers.add_parser("api-resources", help="List available resource types")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "api-resources":
        print_api_resources()
        return

    # --- BASEPATH LOGIC ---
    basepath = getattr(args, "basepath", None)
    if not basepath:
        basepath = get_basepath()

    # --- DEFAULT NAMESPACE LOGIC ---
    # For namespace-scoped resources, if namespace is not provided, use "default"
    if args.command in ("get", "describe", "logs", "top"):
        resource_type = SHORTNAMES.get(getattr(args, "resource", ""), getattr(args, "resource", ""))
        if resource_type in NS_RESOURCES:
            ns_attr = None
            if args.command == "get":
                ns_attr = getattr(args, "namespace", None)
            elif args.command == "describe":
                ns_attr = getattr(args, "namespace", None)
            elif args.command == "logs":
                ns_attr = getattr(args, "namespace", None)
            elif args.command == "top":
                ns_attr = getattr(args, "namespace", None)
            # Only set default if not all-namespaces and not set
            if ns_attr is None and not getattr(args, "all_namespaces", False):
                if args.command == "get":
                    args.namespace = "default"
                elif args.command == "describe":
                    args.namespace = "default"
                elif args.command == "logs":
                    args.namespace = "default"
                elif args.command == "top":
                    args.namespace = "default"

    if args.command == "get":
        resource = SHORTNAMES.get(args.resource, args.resource)
        resource_names = args.resource_names
        namespace = args.namespace
        all_ns_flag = args.all_namespaces
        oyamlmode = args.oyaml
        owidemode = args.owide
        show_labels = args.show_labels

        filter_names = resource_names if resource_names else None

        if resource in NS_RESOURCES:
            if all_ns_flag:
                items = load_namespaced_resources(basepath, resource, None, all_namespaces=True)
                if oyamlmode:
                    print_yaml(items, filter_names=filter_names)
                else:
                    print_resource_table(basepath, resource, items, namespace=None, owidemode=owidemode, all_namespaces=True, filter_names=filter_names)
            elif namespace:
                ns_dir = os.path.join(basepath, namespace)
                if oyamlmode:
                    items = load_namespaced_resources(basepath, resource, namespace)
                    print_yaml(items, filter_names=filter_names)
                else:
                    print_resource_table(basepath, resource, None, namespace=namespace, owidemode=owidemode, show_labels=show_labels, filter_names=filter_names)
            else:
                ns_dir = os.path.join(basepath, "default")
                if oyamlmode:
                    items = load_namespaced_resources(basepath, resource, None, all_namespaces=False)
                    print_yaml(items, filter_names=filter_names)
                else:
                    print_resource_table(basepath, resource, None, namespace="default", owidemode=owidemode, show_labels=show_labels, filter_names=filter_names)
        elif resource in NON_NS_RESOURCES or resource == "namespaces":
            if oyamlmode:
                file_path = os.path.join(basepath, RESOURCE_FILE_MAP.get(resource))
                items = parse_resource_file(file_path)
                print_yaml(items, filter_names=filter_names)
            else:
                if owidemode:
                    file_path = os.path.join(basepath, f"get-owide-{resource}.txt")
                elif show_labels:
                    file_path = os.path.join(basepath, f"get-show-labels-{resource}.txt")
                else:
                    file_path = os.path.join(basepath, f"get-{resource}.txt")
                headers, rows = parse_kubectl_table_file(file_path)
                if not headers:
                    print(f"No data found in {file_path}")
                else:
                    if filter_names:
                        name_idx = None
                        for i, h in enumerate(headers):
                            if h.lower() == "name":
                                name_idx = i
                                break
                        if name_idx is not None:
                            rows = [r for r in rows if r[name_idx] in filter_names]
                    print_kubectl_table(headers, rows)
        elif resource == "all":
            if oyamlmode:
                print("YAML output for 'all' not supported.")
            else:
                results = get_all_resources(basepath, None if all_ns_flag else namespace, all_namespaces=all_ns_flag)
                print_all_table(results, all_namespaces=all_ns_flag, namespace=namespace)
        else:
            print("Unknown resource type: %s" % resource)
            sys.exit(1)

    elif args.command == "top":
        top_resource = args.resource
        namespace = getattr(args, "namespace", None)
        if top_resource == "pods":
            file_path = os.path.join(basepath, "metrics", "pods-usage.txt")
            if not os.path.exists(file_path):
                print(f"No metrics file found: {file_path}")
                sys.exit(1)
            headers, rows = parse_kubectl_table_file(file_path)
            if namespace:
                ns_idx = None
                for i, h in enumerate(headers):
                    if h.lower() in ("namespace", "ns"):
                        ns_idx = i
                        break
                if ns_idx is not None:
                    rows = [r for r in rows if r[ns_idx] == namespace]
            print_kubectl_table(headers, rows)
        elif top_resource == "nodes":
            file_path = os.path.join(basepath, "metrics", "nodes-usage.txt")
            if not os.path.exists(file_path):
                print(f"No metrics file found: {file_path}")
                sys.exit(1)
            headers, rows = parse_kubectl_table_file(file_path)
            print_kubectl_table(headers, rows)
        else:
            print(f"Unsupported top resource: {top_resource}")
            sys.exit(1)

    elif args.command == "logs":
        pod_name = args.pod_name
        namespace = args.namespace
        previous = getattr(args, "previous", False)
        if not namespace:
            print("Namespace must be specified for logs.")
            sys.exit(1)
        log_file_new = os.path.join(basepath, namespace, pod_name, "logs.txt")
        log_file_new_prev = os.path.join(basepath, namespace, pod_name, "logs-previous.txt")
        logs_dir_old = os.path.join(basepath, namespace, "pods-logs")
        log_file_old = os.path.join(logs_dir_old, "%s.log" % pod_name)
        log_file_old_prev = os.path.join(logs_dir_old, "%s.log.previous" % pod_name)
        if previous:
            if os.path.isfile(log_file_new_prev):
                with open(log_file_new_prev, "r") as f:
                    print("=== Previous Logs for %s/%s ===" % (namespace, pod_name))
                    print(f.read())
                return
            elif os.path.isfile(log_file_old_prev):
                with open(log_file_old_prev, "r") as f:
                    print("=== Previous Logs for %s/%s ===" % (namespace, pod_name))
                    print(f.read())
                return
            else:
                print("No previous logs found for pod %s in namespace %s." % (pod_name, namespace))
                return
        if os.path.isfile(log_file_new):
            with open(log_file_new, "r") as f:
                print("=== Logs for %s/%s ===" % (namespace, pod_name))
                print(f.read())
            return
        elif os.path.isfile(log_file_old):
            with open(log_file_old, "r") as f:
                print("=== Logs for %s/%s ===" % (namespace, pod_name))
                print(f.read())
            return
        print("No logs found for pod %s in namespace %s." % (pod_name, namespace))

    elif args.command == "describe":
        resource = SHORTNAMES.get(args.resource, args.resource)
        name = args.name
        namespace = args.namespace
        if resource in NS_RESOURCES and namespace and not name:
            print_describe_for_resource(basepath, resource, namespace, name=None)
        elif name:
            print_describe_for_resource(basepath, resource, namespace, name)
        else:
            describe_path = os.path.join(basepath, "%s-describe.txt" % resource)
            if not os.path.exists(describe_path):
                print("Describe file not found for %s." % resource)
                sys.exit(1)
            with open(describe_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            pattern = re.compile(r"(^|\n)Name:\s*%s(\s|\n|$)" % re.escape(name))
            match = pattern.search(content)
            if match:
                start = match.start(0)
                next_match = re.compile(r"(^|\n)Name:\s*\S+").search(content, match.end())
                end = next_match.start(0) if next_match else len(content)
                print(content[start:end].lstrip("\n"))
                return
            loose_pattern = r"Name:\s*%s" % re.escape(name)
            idx = content.find(loose_pattern)
            if idx != -1:
                next_match = re.compile(r"(^|\n)Name:\s*\S+").search(content, idx + len(loose_pattern))
                end = next_match.start(0) if next_match else len(content)
                print(content[idx:end].lstrip("\n"))
                return
            print("Resource %s not found in describe file." % (name,))

if __name__ == "__main__":
    main()
