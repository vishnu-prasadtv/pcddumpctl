#!/usr/bin/env python3
import yaml
import os
import datetime
import argparse
import sys
import json
from textwrap import dedent
from tabulate import tabulate

VERSION = "1.0.0"

def calculate_age(creation_timestamp, duration_seconds=None):
    """Calculates the age from a creation timestamp or a duration in seconds."""
    if duration_seconds is not None:
        age_seconds = duration_seconds
    elif creation_timestamp:
        try:
            # Handle various ISO 8601 formats, specifically Z for UTC
            if creation_timestamp.endswith('Z'):
                creation_time = datetime.datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
            else:
                creation_time = datetime.datetime.fromisoformat(creation_timestamp)

            # Ensure comparison is timezone-aware
            if creation_time.tzinfo is None:
                creation_time = creation_time.replace(tzinfo=datetime.timezone.utc)

            current_time = datetime.datetime.now(datetime.timezone.utc)
            age_seconds = (current_time - creation_time).total_seconds()
        except ValueError:
            return "N/A"
    else:
        return "N/A"

    if age_seconds < 60:
        return f"{int(age_seconds)}s"
    elif age_seconds < 3600:
        return f"{int(age_seconds / 60)}m"
    elif age_seconds < 86400:
        return f"{int(age_seconds / 3600)}h"
    elif age_seconds < 2592000: # Approx 30 days
        return f"{int(age_seconds / 86400)}d"
    elif age_seconds < 31536000: # Approx 365 days
        return f"{int(age_seconds / 2592000)}mo"
    else:
        return f"{int(age_seconds / 31536000)}y"
    pass


def print_header(title, columns, include_namespace=False):
    """Prints the header for the table."""
    if not columns:
        return

    header_cols = []
    if include_namespace:
        header_cols.append("NAMESPACE".ljust(20))
    header_cols.append("NAME".ljust(40))
    header_cols.extend([col.ljust(15) for col in columns])

    print(f"\n=== {title} ===")
    print("  ".join(header_cols))

    # Print separator line
#    separator = "-" * 20 if include_namespace else ""
#    separator += "  " + "-" * 58
#    separator += "  " + "  ".join(["-" * 15 for _ in columns])
#    print(separator)

def print_pods(pod_list, wide_output=False, yaml_output=False, all_namespaces=False):
    if yaml_output:
        print(yaml.dump(pod_list, sort_keys=False))
        return

    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend(["NAME", "READY", "STATUS", "RESTARTS", "AGE"])
    if wide_output:
        headers.extend(["IP", "NODE", "NOMINATED NODE", "READINESS GATES"])

    table = []

    for pod in pod_list:
        row = []
        namespace = pod.get('metadata', {}).get('namespace', '')
        name = pod.get('metadata', {}).get('name', '')
        status = pod.get('status', {}).get('phase', '')
        if status.lower() == 'succeeded':
            status = 'Completed'

        container_statuses = pod.get('status', {}).get('containerStatuses', [])
        ready_count = sum(1 for c in container_statuses if c.get('ready'))
        total_containers = len(container_statuses)
        restarts = sum(c.get('restartCount', 0) for c in container_statuses)

        age = calculate_age(pod.get('metadata', {}).get('creationTimestamp', ''))

        if all_namespaces:
            row.append(namespace)
        row.extend([
            name,
            f"{ready_count}/{total_containers}",
            status,
            str(restarts),
            age
        ])

        if wide_output:
            ip = pod.get('status', {}).get('podIP', '<none>')
            node = pod.get('spec', {}).get('nodeName', '<none>')
            nominated_node = pod.get('status', {}).get('nominatedNodeName', '<none>')
            readiness_gates = pod.get('spec', {}).get('readinessGates', [])
            readiness_str = ", ".join(g.get('conditionType', '') for g in readiness_gates) if readiness_gates else '<none>'
            row.extend([ip, node, nominated_node, readiness_str])

        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="plain"))

def print_deployments(deployment_list, wide_output=False, all_namespaces=False):
    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend(["NAME", "READY", "UP-TO-DATE", "AVAILABLE", "AGE"])

    table = []

    for deployment in deployment_list:
        name = deployment.get('metadata', {}).get('name', '')
        namespace = deployment.get('metadata', {}).get('namespace', '')
        replicas = deployment.get('spec', {}).get('replicas', 0)
        updated_replicas = deployment.get('status', {}).get('updatedReplicas', 0)
        available_replicas = deployment.get('status', {}).get('availableReplicas', 0)
        age = calculate_age(deployment.get('metadata', {}).get('creationTimestamp', ''))

        row = []
        if all_namespaces:
            row.append(namespace)
        row.extend([
            name,
            f"{available_replicas}/{replicas}",
            str(updated_replicas),
            str(available_replicas),
            age
        ])
        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="plain"))

def print_statefulsets(statefulset_list, wide_output=False, all_namespaces=False):
    """Prints the statefulset details using tabulate."""
    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend(["NAME", "READY", "AGE"])

    table = []

    for sts in statefulset_list:
        name = sts.get('metadata', {}).get('name', '')
        namespace = sts.get('metadata', {}).get('namespace', '')

        replicas = sts.get('spec', {}).get('replicas', 0)
        ready_replicas = sts.get('status', {}).get('readyReplicas', 0)
        age = calculate_age(sts.get('metadata', {}).get('creationTimestamp', ''))

        row = []
        if all_namespaces:
            row.append(namespace)
        row.extend([
            name,
            f"{ready_replicas}/{replicas}",
            age
        ])

        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="plain"))

def print_daemonsets(daemonset_list, wide_output=False, all_namespaces=False):
    """Prints the daemonset details using tabulate."""
    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend([
        "NAME", "DESIRED", "CURRENT", "READY", "UP-TO-DATE",
        "AVAILABLE", "NODE SELECTOR", "AGE"
    ])

    table = []

    for ds in daemonset_list:
        name = ds.get('metadata', {}).get('name', '')
        namespace = ds.get('metadata', {}).get('namespace', '')

        desired = ds.get('status', {}).get('desiredNumberScheduled', 0)
        current = ds.get('status', {}).get('currentNumberScheduled', 0)
        ready = ds.get('status', {}).get('numberReady', 0)
        up_to_date = ds.get('status', {}).get('updatedNumberScheduled', 0)
        available = ds.get('status', {}).get('numberAvailable', 0)

        node_selector = ds.get('spec', {}).get('template', {}).get('spec', {}).get('nodeSelector', {})
        node_selector_str = ", ".join([f"{k}={v}" for k, v in node_selector.items()]) if node_selector else '<none>'

        age = calculate_age(ds.get('metadata', {}).get('creationTimestamp', ''))

        row = []
        if all_namespaces:
            row.append(namespace)
        row.extend([
            name,
            str(desired),
            str(current),
            str(ready),
            str(up_to_date),
            str(available),
            node_selector_str,
            age
        ])
        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="plain"))

def print_services(service_list, wide_output=False, all_namespaces=False):
    """Prints the service details using tabulate."""
    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend(["NAME", "TYPE", "CLUSTER-IP", "EXTERNAL-IP", "PORT(S)", "AGE"])

    table = []

    for service in service_list:
        name = service.get('metadata', {}).get('name', '')
        namespace = service.get('metadata', {}).get('namespace', '')

        service_type = service.get('spec', {}).get('type', '')
        cluster_ip = service.get('spec', {}).get('clusterIP', '')
        external_ip = '<none>'

        if service_type == 'LoadBalancer':
            ingress = service.get('status', {}).get('loadBalancer', {}).get('ingress', [])
            if ingress:
                external_ip = ingress[0].get('ip', ingress[0].get('hostname', '<pending>'))
        elif service_type == 'ExternalName':
            external_ip = service.get('spec', {}).get('externalName', '<none>')

        ports = ", ".join(
            f"{port['port']}:{port.get('nodePort', '')}/{port['protocol']}"
            if 'nodePort' in port else f"{port['port']}/{port['protocol']}"
            for port in service.get('spec', {}).get('ports', [])
        )

        age = calculate_age(service.get('metadata', {}).get('creationTimestamp', ''))

        row = []
        if all_namespaces:
            row.append(namespace)
        row.extend([name, service_type, cluster_ip, external_ip, ports, age])
        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="plain"))

def print_events(event_list, wide_output=False, all_namespaces=False):
    """Prints the event details."""
    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend(["NAME", "LAST SEEN", "TYPE", "REASON", "OBJECT", "MESSAGE"])

    event_list = sorted(event_list, key=lambda e: e.get('lastTimestamp') or e.get('eventTime') or '', reverse=False)

    table_data = []
    for event in event_list:
        namespace = event.get('metadata', {}).get('namespace', '')
        last_timestamp = event.get('lastTimestamp', event.get('eventTime', ''))
        event_type = event.get('type', '')
        reason = event.get('reason', '')
        involved_object = event.get('involvedObject', {})
        obj_name = involved_object.get('name', '')
        obj_kind = involved_object.get('kind', '')
        obj_field_path = involved_object.get('fieldPath', '')
        obj_str = f"{obj_kind}/{obj_name}"
        if obj_field_path:
            obj_str += f" ({obj_field_path})"
        message = event.get('message', '')

        row_data = []
        if all_namespaces:
            row_data.append(namespace)
        row_data.extend([obj_name, last_timestamp, event_type, reason, obj_str, message])
        table_data.append(row_data)

    print(tabulate(table_data, headers=headers, tablefmt="plain"))
def print_replicasets(replicaset_list, wide_output=False, all_namespaces=False):
    """Prints the replicaset details using tabulate."""
    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend(["NAME", "DESIRED", "CURRENT", "READY", "AGE"])

    table = []

    for rs in replicaset_list:
        name = rs.get('metadata', {}).get('name', '')
        namespace = rs.get('metadata', {}).get('namespace', '')

        desired = rs.get('spec', {}).get('replicas', 0)
        current = rs.get('status', {}).get('replicas', 0)
        ready = rs.get('status', {}).get('readyReplicas', 0)
        age = calculate_age(rs.get('metadata', {}).get('creationTimestamp', ''))

        row = []
        if all_namespaces:
            row.append(namespace)
        row.extend([name, desired, current, ready, age])
        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="plain"))

def print_jobs(job_list, wide_output=False, all_namespaces=False):
    """Prints the job details using tabulate."""
    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend(["NAME", "COMPLETIONS", "DURATION", "AGE"])

    table = []

    for job in job_list:
        name = job.get('metadata', {}).get('name', '')
        namespace = job.get('metadata', {}).get('namespace', '')

        completions = job.get('status', {}).get('succeeded', 0)
        start_time = job.get('status', {}).get('startTime')
        completion_time = job.get('status', {}).get('completionTime')

        duration = "N/A"
        if start_time and completion_time:
            try:
                start = datetime.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                end = datetime.datetime.fromisoformat(completion_time.replace('Z', '+00:00'))
                duration_seconds = (end - start).total_seconds()
                duration = calculate_age(None, duration_seconds)
            except ValueError:
                pass

        age = calculate_age(job.get('metadata', {}).get('creationTimestamp', ''))

        row = []
        if all_namespaces:
            row.append(namespace)
        row.extend([name, completions, duration, age])
        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="plain"))

def print_cronjobs(cronjob_list, wide_output=False, all_namespaces=False):
    """Prints the cronjob details using tabulate."""
    headers = []
    if all_namespaces:
        headers.append("NAMESPACE")
    headers.extend(["NAME", "SCHEDULE", "SUSPEND", "LAST SCHEDULE", "AGE"])

    table = []

    for cj in cronjob_list:
        name = cj.get('metadata', {}).get('name', '')
        namespace = cj.get('metadata', {}).get('namespace', '')

        schedule = cj.get('spec', {}).get('schedule', '')
        suspend = cj.get('spec', {}).get('suspend', False)
        last_schedule_time = cj.get('status', {}).get('lastScheduleTime')
        last_schedule = calculate_age(last_schedule_time) if last_schedule_time else '<none>'
        age = calculate_age(cj.get('metadata', {}).get('creationTimestamp', ''))

        row = []
        if all_namespaces:
            row.append(namespace)
        row.extend([name, schedule, str(suspend), last_schedule, age])
        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="plain"))

def print_nodes(node_list, wide_output=False):
    """Prints the node details."""
    columns = ["STATUS", "ROLES", "AGE", "VERSION"]
    if wide_output:
        columns.insert(2, "INTERNAL-IP")
        columns.insert(3, "EXTERNAL-IP")

    print_header("Nodes", columns, include_namespace=False)

    for node in node_list:
        name = node.get('metadata', {}).get('name', '')

        status_conditions = node.get('status', {}).get('conditions', [])
        ready_condition = next((cond for cond in status_conditions if cond.get('type') == 'Ready'), None)
        status = ready_condition.get('status', 'Unknown') if ready_condition else 'Unknown'

        roles = []
        labels = node.get('metadata', {}).get('labels', {})
        if 'node-role.kubernetes.io/master' in labels:
            roles.append('master')
        if 'node-role.kubernetes.io/control-plane' in labels:
            roles.append('control-plane')

        if not roles:
            roles.append('<none>')
        roles_str = ",".join(roles)

        age = calculate_age(node.get('metadata', {}).get('creationTimestamp', ''))
        version = node.get('status', {}).get('nodeInfo', {}).get('kubeletVersion', '')

        row_data = [
            name.ljust(40),
            status.ljust(15),
            roles_str.ljust(15)
        ]

        if wide_output:
            internal_ip = next(
                (addr['address'] for addr in node.get('status', {}).get('addresses', [])
                 if addr['type'] == 'InternalIP'),
                '<none>'
            )
            external_ip = next(
                (addr['address'] for addr in node.get('status', {}).get('addresses', [])
                 if addr['type'] == 'ExternalIP'),
                '<none>'
            )
            row_data.extend([
                internal_ip.ljust(15),
                external_ip.ljust(15)
            ])

        row_data.extend([
            age.ljust(15),
            version
        ])

        print("  ".join(row_data))

def parse_resource_file(file_path):
    """Parses a YAML, JSON, or JSON Lines file and returns a list of resource items."""
    if not os.path.exists(file_path):
        return []

    items = []

    try:
        with open(file_path, 'r') as file:
            if file_path.endswith('.json') or file_path.endswith('.txt'):
                # Handle JSON Lines
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        items.append(obj)
                    except json.JSONDecodeError as e:
                        print(f"Skipping malformed JSON line: {e}", file=sys.stderr)
                return items
            else:
                # Handle regular YAML
                parsed_output = yaml.safe_load(file)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}", file=sys.stderr)
        return []

    if parsed_output is None:
        return []

    if 'items' in parsed_output:
        items = parsed_output['items']
    elif isinstance(parsed_output, dict) and 'apiVersion' in parsed_output and 'kind' in parsed_output:
        items = [parsed_output]
    elif isinstance(parsed_output, list):
        items = parsed_output

    return items

def parse_json_lines_file(file_path):
    """Parses a file with newline-delimited JSON objects."""
    if not os.path.exists(file_path):
        return []

    items = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                items.append(obj)
            except json.JSONDecodeError as e:
                print(f"Skipping malformed JSON line: {e}", file=sys.stderr)
    return items

def print_hosts(host_list, wide_output=False):
    """Prints host details from the resmgr_json.txt file."""
    from tabulate import tabulate

    headers = ["HOSTNAME", "HOST_ID", "STATUS", "IP"]
    rows = []

    for item in host_list:
        host = item 

        # Correctly access the nested hostname
        hostname = host.get("info", {}).get("hostname", "<none>")

        # Use the correct key for host_id
        host_id = host.get("host_id", "<none>")

        # Status is correctly at the top level
        status = host.get("status", "<none>")

        # Correctly access the nested IP address list
        ip_list = host.get("extensions", {}).get("ip_address", {}).get("data", [])
        ip = ip_list[0] if ip_list else "<none>"

        rows.append([hostname, host_id, status, ip])

    print("\n=== Hosts ===")
    print(tabulate(rows, headers=headers, tablefmt="plain"))

def get_pod_logs(namespace_path, pod_name):
    """Fetches and prints logs for a specific pod with corrected path."""
    # Correct path: namespace_path/pod_name/logs.txt
    logs_path = os.path.join(namespace_path, pod_name, 'logs.txt')

    if os.path.exists(logs_path):
        print(f"\n=== Logs for Pod: {pod_name} in namespace {os.path.basename(namespace_path)} ===")
        try:
            with open(logs_path, 'r') as log_file:
                print(log_file.read())
        except Exception as e:
            print(f"Error reading logs: {e}", file=sys.stderr)
    else:
        print(f"No logs found for pod: {pod_name} at {logs_path}", file=sys.stderr)
def print_namespaces(namespace_dirs):
    print("\n=== Namespaces ===")
    print("NAME".ljust(40))
    print("-" * 40)
    for ns in sorted(namespace_dirs):
        print(ns.ljust(40))
def main():
    # Check if running from cluster-dump directory
    #    cwd = os.getcwd()
    base_dump_path = os.environ.get("CLUSTER_DUMP_PATH")
    if not base_dump_path:
        print("Error: Please set the CLUSTER_DUMP_PATH environment variable.", file=sys.stderr)
        print("Example: export CLUSTER_DUMP_PATH=/path/to/your/cluster-dump", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(base_dump_path):
        print(f"Error: CLUSTER_DUMP_PATH '{base_dump_path}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Platform9 Cluster Dump Inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""\
        Examples:
          # List all events across all namespaces
          pf9dumpctl get events -A

          # List pods in specific namespace with wide output
          pf9dumpctl get pods -n kube-system -o wide

          # View logs for a specific pod
          pf9dumpctl logs <pod-name> -n <namespace>

          # List all available namespaces
          pf9dumpctl get namespaces

          # List all available resource types
          pf9dumpctl get all

        Supported Resource Types:
          pods, deployments, statefulsets, daemonsets, replicasets,
          services, events, jobs, cronjobs, nodes, logs, hosts
        """))

#    parser.add_argument("resource_type", nargs='?', choices=[
#       "pods", "deployments", "statefulsets", "daemonsets", "replicasets",
#       "services", "events", "jobs", "cronjobs", "nodes", "logs"
#    ], help="The type of Kubernetes resource to query")
#    parser.add_argument("-n", "--namespace", help="Filter by namespace")
    parser.add_argument("--all-namespaces", "-A", action="store_true",
                       help="Query all namespaces")
    parser.add_argument("-o", "--output", choices=["wide"],
                       help="Output format (wide for extended information)")
    parser.add_argument("-o", "--output", choices=["yaml"],
                       help="Output format (yaml for extended information)")
#    parser.add_argument("pods", help="Specify pod name for logs")
#    parser.add_argument("--list-resources", action="store_true",
#                       help="List all available resource types")
#    parser.add_argument("--list-namespaces", action="store_true",
#                       help="List all available namespaces")
    parser.add_argument("--version", action="version",
                       version=f"%(prog)s {VERSION}",
                       help="Show version and exit")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommand (get, describe)")
#get command parser
    get_parser = subparsers.add_parser("get", help="Get kubernetes resources")
    valid_resource_types = [
    "pods", "deployments", "statefulsets", "daemonsets", "replicasets",
    "services", "events", "jobs", "cronjobs", "nodes", "namespaces", "all", "hosts"
    ]
    get_parser.add_argument("resource_type", nargs='?', choices=valid_resource_types, help="The type of Kubernetes resource to query")
    get_parser.add_argument("resource_target", nargs="?", help="For 'logs', specify pod name")
    get_parser.add_argument("-n", "--namespace", help="Filter by namespace")
    get_parser.add_argument("-A", "--all-namespaces", action="store_true", help="Query all namespaces")
    get_parser.add_argument("-o", "--output", choices=["wide","yaml"], help="Output format (wide or yaml for extended information)")
#    get_parser.add_argument("pods", help="Specify pod name for logs")

#describe command parser
    describe_parser = subparsers.add_parser("describe", help="Describe a specific resource")
    describe_parser.add_argument("resource_type", choices=[
        "pods", "deployments", "statefulsets", "daemonsets", "replicasets",
        "services", "events", "jobs", "cronjobs", "nodes"
    ])
    describe_parser.add_argument("name", help="Name of the resource")
    describe_parser.add_argument("-n", "--namespace", required=True, help="Namespace of the resource")
    describe_parser.add_argument("-o", "--output", choices=["yaml"], help="output format")
    describe_parser.add_argument("resource_target", nargs="?", help="Optional name of the resource to print in YAML")

    logs_parser = subparsers.add_parser("logs", help="show pod specific logs")
    logs_parser.add_argument("pod_name", help="pod name to show logs for")
    logs_parser.add_argument("-n","--namespace", required=True, help="Namespace of the pod")

    args = parser.parse_args()

    # Validate arguments
#    if args.resource_type == "logs" and not (args.namespace and args.pod_name):
#        print("Error: For 'logs' resource type, both --namespace and --pod-name are required", file=sys.stderr)
#        sys.exit(1)

#    if not args.resource_type and not (args.list_resources or args.list_namespaces):
#        parser.print_help()
#        sys.exit(1)
    non_namespaced_resources = {"nodes", "namespaces", "hosts"}
    """
    if args.command == "get":
        is_namespaced = args.resource_type not in non_namespaced_resources

    if is_namespaced and not (args.namespace or args.all_namespaces):
        print("Error: Please specify a namespace with -n/--namespace or use --all-namespaces.", file=sys.stderr)
        sys.exit(1)

    if not is_namespaced:
        args.namespace = None
        args.all_namespaces = False
    """
    if args.command == "get" and args.resource_type == "logs":
        if not args.resource_target or not args.namespace:
            print("Error: For 'get logs', both POD_NAME and --namespace are required", file=sys.stderr)
            print("Usage: pf9dumpctl get logs POD_NAME -n NAMESPACE")
        sys.exit(1)
        
    # Fetch pod logs (adjust path to your cluster dump layout if needed)
        pod_name = args.resource_target
        namespace = args.namespace
        log_path = os.path.join(base_dump_path, namespace, "pod_logs", f"{pod_name}.log")

        if os.path.exists(log_path):
            print(f"\n=== Logs for Pod '{pod_name}' in Namespace '{namespace}' ===\n")
            with open(log_path, 'r') as f:
                print(f.read())
        else:
            print(f"No logs found for pod '{pod_name}' in namespace '{namespace}'", file=sys.stderr)
        sys.exit(0)
    
    if args.command == "get" and args.resource_type == "all":
        if not args.namespace and not args.all_namespaces:
            args.all_namespaces = True

    if args.command == "logs":
        namespace_path = os.path.join(base_dump_path, args.namespace)
        if not os.path.isdir(namespace_path):
            print(f"Error: Namespace '{args.namespace}' not found in the dump.", file=sys.stderr)
            sys.exit(1)

        get_pod_logs(namespace_path, args.pod_name)
        sys.exit(0)

    

    if args.command == "describe":
        base_dump_path = os.getcwd()

        resource_filename_map = {
        "pods": "pods.yaml",
        "deployments": "deployments.yaml",
        "statefulsets": "statefulsets.yaml",
        "daemonsets": "daemonsets.yaml",
        "replicasets": "replicasets.yaml",
        "services": "services.yaml",
        "events": "events.yaml",
        "jobs": "jobs.yaml",
        "cronjobs": "cronjobs.yaml",
        "nodes": "nodes.yaml",
    }

        if args.resource_type == "nodes":
            resource_path = os.path.join(base_dump_path, "nodes.yaml")
        else:
            namespace_path = os.path.join(base_dump_path, args.namespace)
            if not os.path.isdir(namespace_path):
                print(f"Error: Namespace '{args.namespace}' not found.", file=sys.stderr)
                sys.exit(1)

            resource_path = os.path.join(namespace_path, resource_filename_map[args.resource_type])

        if not os.path.exists(resource_path):
            print(f"No resource file found at: {resource_path}", file=sys.stderr)
            sys.exit(1)

        items = parse_resource_file(resource_path)
        matched = [res for res in items if res.get('metadata', {}).get('name') == args.name]

        if not matched:
            print(f"{args.resource_type} '{args.name}' not found in namespace '{args.namespace}'", file=sys.stderr)
            sys.exit(1)
        """   
        if args.output == "yaml":
            if args.resource_target:
                matched = [
                    res for res in all_collected_resources
                    if res.get("metadata", {}).get("name") == args.resource_target
                ]
                if matched:
                    print(yaml.dump(matched[0], sort_keys=False))
                else:
                    print(f"{args.resource_type} '{args.resource_target}' not found in namespace '{args.namespace}'", file=sys.stderr)
            else:
                print(yaml.dump(all_collected_resources, sort_keys=False))
            sys.exit(0)
        print(f"\n=== Description of {args.resource_type} '{args.name}' in namespace '{args.namespace}' ===")
        print(yaml.dump(matched[0], sort_keys=False))
        sys.exit(0)
        """
        """
        if args.resource_target:
            matched = [
                res for res in all_collected_resources
                if res.get("metadata", {}).get("name") == args.name
                ]
            if matched:
                print(yaml.dump(matched[0], sort_keys=False))
            else:
                print(f"Resource '{args.resource_target}' not found in the specified namespace(s).")
        else:
            # No specific pod name; dump all resources in YAML
                if all_collected_resources:
                    print(yaml.dump(all_collected_resources, sort_keys=False))
                else:
                    print(f"No {resource_display_name} found in the specified namespace(s).")
        sys.exit(0)
        """
        if args.output == "yaml":
            print(yaml.dump(matched[0], sort_keys=False))
            sys.exit(0)

# Default describe output (not yaml)
        print(f"\n=== Description of {args.resource_type} '{args.name}' in namespace '{args.namespace}' ===")
        print(yaml.dump(matched[0], sort_keys=False))
        sys.exit(0)
#    base_dump_path = os.getcwd()

    resource_map = {
        "pods": {"file": "pods.yaml", "display": "Pods", "printer": print_pods},
        "deployments": {"file": "deployments.yaml", "display": "Deployments", "printer": print_deployments},
        "statefulsets": {"file": "statefulsets.yaml", "display": "StatefulSets", "printer": print_statefulsets},
        "daemonsets": {"file": "daemonsets.yaml", "display": "DaemonSets", "printer": print_daemonsets},
        "replicasets": {"file": "replicasets.yaml", "display": "ReplicaSets", "printer": print_replicasets},
        "services": {"file": "services.yaml", "display": "Services", "printer": print_services},
        "events": {"file": "events.yaml", "display": "Events", "printer": print_events},
        "jobs": {"file": "jobs.yaml", "display": "Jobs", "printer": print_jobs},
        "cronjobs": {"file": "cronjobs.yaml", "display": "CronJobs", "printer": print_cronjobs},
        "nodes": {"file": "nodes.yaml", "display": "Nodes", "printer": print_nodes},
        "namespaces": {"file": None, "display": "Namespaces", "printer": lambda ns_list, **kwargs: print_namespaces(ns_list)}
    }

    if args.command == "get" and args.resource_type == "hosts":
        hosts_file_path = os.path.join(base_dump_path, "resmgr_json.txt")
        if not os.path.exists(hosts_file_path):
            print(f"Error: hosts file not found at {hosts_file_path}", file=sys.stderr)
            sys.exit(1)

        host_data = parse_json_lines_file(hosts_file_path)
        if len(host_data) == 1 and isinstance(host_data[0], list):
            host_data = host_data[0]

        if not host_data:
            print("No hosts data found.")
            sys.exit(1)

        if args.output == "yaml":
            print(yaml.dump(host_data, sort_keys=False))
        else:
            print_hosts(host_data, wide_output=(args.output == "wide"))
        sys.exit(0)

    if args.list_resources:
        print("\n=== Available Resource Types ===")
        for r_type in resource_map.keys():
            print(f"- {r_type}")
        sys.exit(0)

    if args.list_namespaces:
        print("\n=== Available Namespaces ===")
        found_namespaces = [d for d in os.listdir(base_dump_path)
                           if os.path.isdir(os.path.join(base_dump_path, d))
                           and not d.startswith('.')]
        if found_namespaces:
            for ns in sorted(found_namespaces):
                print(f"- {ns}")
        else:
            print("No namespaces found in the cluster dump directory.")
        sys.exit(0)

    if args.resource_type == "all":
        print("\n=== Showing all supported resources ===\n")
        for rtype in [
            "pods", "deployments", "statefulsets", "daemonsets", "replicasets",
            "services", "jobs", "cronjobs", "nodes"
        ]:
            selected_resource_info = resource_map.get(rtype)
            if not selected_resource_info:
                continue

            resource_filename = selected_resource_info["file"]
            resource_display_name = selected_resource_info["display"]
            resource_printer = selected_resource_info["printer"]

            all_collected_resources = []

            if rtype == "nodes":
                nodes_file_path = os.path.join(base_dump_path, "nodes.yaml")
                nodes_list = parse_resource_file(nodes_file_path)
                if nodes_list:
                    print(f"\n=== {resource_display_name} ===")
                    resource_printer(nodes_list, wide_output=(args.output == "wide"))
                continue

            if args.all_namespaces:
                namespaces_to_process = [d for d in os.listdir(base_dump_path)
                                         if os.path.isdir(os.path.join(base_dump_path, d))
                                         and not d.startswith('.')]
            elif args.namespace:
                namespaces_to_process = [args.namespace]
            else:
                print("Error: Please specify a namespace with -n/--namespace or use --all-namespaces.", file=sys.stderr)
                sys.exit(1)

            for namespace in namespaces_to_process:
                namespace_path = os.path.join(base_dump_path, namespace)
                resource_path = os.path.join(namespace_path, resource_filename)
                if not os.path.exists(resource_path):
                    continue
                items = parse_resource_file(resource_path)
                for res in items:
                    if 'metadata' in res and 'namespace' not in res['metadata']:
                        res['metadata']['namespace'] = namespace
                all_collected_resources.extend(items)

            if all_collected_resources:
                print(f"\n=== {resource_display_name} ===")
                resource_printer(all_collected_resources,
                                 wide_output=(args.output == "wide"),
                                 all_namespaces=args.all_namespaces)
            else:
                print(f"No {resource_display_name} found.")

        sys.exit(0) 

    if args.resource_type == "namespaces":
        namespace_dirs = [d for d in os.listdir(base_dump_path)
                          if os.path.isdir(os.path.join(base_dump_path, d)) and not d.startswith('.')]
        if namespace_dirs:
            print_namespaces(namespace_dirs)
        else:
            print("No namespaces found in the cluster dump directory.")
        sys.exit(0)

    # Handle 'nodes' which are typically at the root, not in namespaces
    if args.resource_type == "nodes":
        nodes_file_path = os.path.join(base_dump_path, "nodes.yaml")
        nodes_list = parse_resource_file(nodes_file_path)
        print_nodes(nodes_list, wide_output=(args.output == "wide"))
        sys.exit(0)

    # Handle 'logs' specifically
    if args.resource_type == "logs":
        namespace_path = os.path.join(base_dump_path, args.namespace)
        if not os.path.isdir(namespace_path):
            print(f"Error: Namespace '{args.namespace}' not found in the dump.", file=sys.stderr)
            sys.exit(1)

        get_pod_logs(namespace_path, args.pod_name)
        sys.exit(0)

    # Determine namespaces to search for other resource types
    namespaces_to_process = []
    if args.all_namespaces:
        namespaces_to_process = [d for d in os.listdir(base_dump_path)
                                if os.path.isdir(os.path.join(base_dump_path, d))
                                and not d.startswith('.')]
    elif args.namespace:
        if not os.path.isdir(os.path.join(base_dump_path, args.namespace)):
            print(f"Error: Namespace '{args.namespace}' not found in the cluster dump.", file=sys.stderr)
            sys.exit(1)
        namespaces_to_process = [args.namespace]
    else:
        print("Error: Please specify a namespace with -n/--namespace or use --all-namespaces.", file=sys.stderr)
        sys.exit(1)

    selected_resource_info = resource_map.get(args.resource_type)
    if not selected_resource_info:
        print(f"Error: Resource type '{args.resource_type}' is not supported for namespace-based queries.", file=sys.stderr)
        sys.exit(1)

    resource_filename = selected_resource_info["file"]
    resource_display_name = selected_resource_info["display"]
    resource_printer = selected_resource_info["printer"]

    all_collected_resources = []

    for namespace in namespaces_to_process:
        namespace_path = os.path.join(base_dump_path, namespace)
        resource_path = os.path.join(namespace_path, resource_filename)

        current_namespace_resources = []

        if args.resource_type == "pods":
            # Check for a single pods.yaml first
            if os.path.exists(resource_path):
                current_namespace_resources = parse_resource_file(resource_path)
            else:
                # If not, assume individual pod YAMLs inside the namespace directory
                for pod_folder in os.listdir(namespace_path):
                    pod_folder_path = os.path.join(namespace_path, pod_folder)
                    if os.path.isdir(pod_folder_path):
                        pod_yaml_path = os.path.join(pod_folder_path, 'pod.yaml')
                        if os.path.exists(pod_yaml_path):
                            pod_data = parse_resource_file(pod_yaml_path)
                            if pod_data:
                                # Ensure namespace is set in metadata for consistency
                                if 'metadata' in pod_data[0] and 'namespace' not in pod_data[0]['metadata']:
                                    pod_data[0]['metadata']['namespace'] = namespace
                                current_namespace_resources.extend(pod_data)
        else:
            # For other resource types, just parse the main resource file
            current_namespace_resources = parse_resource_file(resource_path)
            # Ensure namespace is set in metadata for consistency for all resources
            for res in current_namespace_resources:
                if 'metadata' in res and 'namespace' not in res['metadata']:
                    res['metadata']['namespace'] = namespace

        all_collected_resources.extend(current_namespace_resources)
    """
    if args.output == "yaml" and args.resource_type == "pods":
        if args.resource_target:
            matched = [
                res for res in all_collected_resources
                if res.get("metadata", {}).get("name") == args.resource_target
            ]
            if matched:
                print(yaml.dump(matched[0], sort_keys=False))
            else:
                print(f"Pod '{args.resource_target}' not found in specified namespace(s).", file=sys.stderr)
        else:
            if all_collected_resources:
                print(yaml.dump(all_collected_resources, sort_keys=False))
            else:
                if args.all_namespaces:
                    print("No pods found across all namespaces.", file=sys.stderr)
                else:
                    print(f"No pods found in namespace '{args.namespace}'.", file=sys.stderr)
        sys.exit(0)
    """

    if args.output == "yaml" and args.resource_target:
        matched = [
            res for res in all_collected_resources
            if res.get("metadata", {}).get("name") == args.resource_target
        ]
        if matched:
            print(yaml.dump(matched[0], sort_keys=False))
        else:
            print(f"{args.resource_type} '{args.resource_target}' not found in specified namespace(s).", file=sys.stderr)
        sys.exit(0)

    if args.all_namespaces:
        if all_collected_resources:
            resource_printer(all_collected_resources,
                         wide_output=(args.output == "wide"),
                         all_namespaces=True)
        else:
            print(f"No {resource_display_name} found across all namespaces.")
    else:
        if all_collected_resources:
            print(f"\n--- Namespace: {args.namespace} ---")
            resource_printer(all_collected_resources,
                         wide_output=(args.output == "wide"),
                         all_namespaces=False)
        else:
            print(f"No {resource_display_name} found in namespace '{args.namespace}'.")

if __name__ == "__main__":
    main()
