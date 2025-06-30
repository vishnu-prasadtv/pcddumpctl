#!/usr/bin/env python3
import yaml
import os
import datetime
import argparse
import sys
from textwrap import dedent

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

def print_header(title, columns, include_namespace=False):
    """Prints the header for the table."""
    if not columns:
        return

    header_cols = []
    if include_namespace:
        header_cols.append("NAMESPACE".ljust(20))
    header_cols.append("NAME".ljust(58))
    header_cols.extend([col.ljust(15) for col in columns])

    print(f"\n=== {title} ===")
    print("  ".join(header_cols))

    # Print separator line
    separator = "-" * 20 if include_namespace else ""
    separator += "  " + "-" * 58
    separator += "  " + "  ".join(["-" * 15 for _ in columns])
    print(separator)

def print_pods(pod_list, wide_output=False, all_namespaces=False):
    """Prints the pod details."""
    columns = ["READY", "STATUS", "RESTARTS", "AGE"]
    if wide_output:
        columns.extend(["IP", "NODE", "NOMINATED NODE", "READINESS GATES"])

    print_header("Pods", columns, include_namespace=all_namespaces)

    for pod in pod_list:
        name = pod.get('metadata', {}).get('name', '')
        namespace = pod.get('metadata', {}).get('namespace', '')

        status = pod.get('status', {}).get('phase', '')
        # Handle completed pods
        if status.lower() == 'succeeded':
            status = 'Completed'

        container_statuses = pod.get('status', {}).get('containerStatuses', [])

        ready_count = 0
        total_containers = 0
        restarts = 0

        if container_statuses:
            total_containers = len(container_statuses)
            for container in container_statuses:
                if container.get('ready', False):
                    ready_count += 1
                restarts += container.get('restartCount', 0)

        ready_str = f"{ready_count}/{total_containers}"
        age = calculate_age(pod.get('metadata', {}).get('creationTimestamp', ''))

        row_data = []
        if all_namespaces:
            row_data.append(namespace.ljust(20))
        row_data.extend([
            name.ljust(58),
            ready_str.ljust(15),
            status.ljust(15),
            str(restarts).ljust(15),
            age.ljust(15)
        ])

        if wide_output:
            ip = pod.get('status', {}).get('podIP', '<none>').ljust(15)
            node = pod.get('spec', {}).get('nodeName', '<none>').ljust(15)
            nominated_node = pod.get('status', {}).get('nominatedNodeName', '<none>').ljust(15)
            readiness_gates = pod.get('spec', {}).get('readinessGates', [])
            readiness_gates_str = ", ".join(
                [gate.get('conditionType', '') for gate in readiness_gates]
            ) if readiness_gates else '<none>'
            row_data.extend([ip, node, nominated_node, readiness_gates_str.ljust(15)])

        print("  ".join(row_data))

def print_deployments(deployment_list, wide_output=False, all_namespaces=False):
    """Prints the deployment details."""
    columns = ["READY", "UP-TO-DATE", "AVAILABLE", "AGE"]
    print_header("Deployments", columns, include_namespace=all_namespaces)

    for deployment in deployment_list:
        name = deployment.get('metadata', {}).get('name', '')
        namespace = deployment.get('metadata', {}).get('namespace', '')

        replicas = deployment.get('spec', {}).get('replicas', 0)
        updated_replicas = deployment.get('status', {}).get('updatedReplicas', 0)
        available_replicas = deployment.get('status', {}).get('availableReplicas', 0)
        age = calculate_age(deployment.get('metadata', {}).get('creationTimestamp', ''))

        row_data = []
        if all_namespaces:
            row_data.append(namespace.ljust(20))
        row_data.extend([
            name.ljust(58),
            f"{available_replicas}/{replicas}".ljust(15),
            str(updated_replicas).ljust(15),
            str(available_replicas).ljust(15),
            age.ljust(15)
        ])

        print("  ".join(row_data))

def print_statefulsets(statefulset_list, wide_output=False, all_namespaces=False):
    """Prints the statefulset details."""
    columns = ["READY", "AGE"]
    print_header("StatefulSets", columns, include_namespace=all_namespaces)

    for sts in statefulset_list:
        name = sts.get('metadata', {}).get('name', '')
        namespace = sts.get('metadata', {}).get('namespace', '')

        replicas = sts.get('spec', {}).get('replicas', 0)
        ready_replicas = sts.get('status', {}).get('readyReplicas', 0)
        age = calculate_age(sts.get('metadata', {}).get('creationTimestamp', ''))

        row_data = []
        if all_namespaces:
            row_data.append(namespace.ljust(20))
        row_data.extend([
            name.ljust(58),
            f"{ready_replicas}/{replicas}".ljust(15),
            age.ljust(15)
        ])

        print("  ".join(row_data))

def print_daemonsets(daemonset_list, wide_output=False, all_namespaces=False):
    """Prints the daemonset details."""
    columns = ["DESIRED", "CURRENT", "READY", "UP-TO-DATE", "AVAILABLE", "NODE SELECTOR", "AGE"]
    print_header("DaemonSets", columns, include_namespace=all_namespaces)

    for ds in daemonset_list:
        name = ds.get('metadata', {}).get('name', '')
        namespace = ds.get('metadata', {}).get('namespace', '')

        desired = ds.get('status', {}).get('desiredNumberScheduled', 0)
        current = ds.get('status', {}).get('currentNumberScheduled', 0)
        ready = ds.get('status', {}).get('numberReady', 0)
        up_to_date = ds.get('status', {}).get('updatedNumberScheduled', 0)
        available = ds.get('status', {}).get('numberAvailable', 0)
        node_selector = ds.get('spec', {}).get('template', {}).get('spec', {}).get('nodeSelector', {})
        node_selector_str = ", ".join([f"{k}={v}" for k,v in node_selector.items()]) if node_selector else '<none>'
        age = calculate_age(ds.get('metadata', {}).get('creationTimestamp', ''))

        row_data = []
        if all_namespaces:
            row_data.append(namespace.ljust(20))
        row_data.extend([
            name.ljust(58),
            str(desired).ljust(15),
            str(current).ljust(15),
            str(ready).ljust(15),
            str(up_to_date).ljust(15),
            str(available).ljust(15),
            node_selector_str.ljust(15),
            age.ljust(15)
        ])

        print("  ".join(row_data))

def print_services(service_list, wide_output=False, all_namespaces=False):
    """Prints the service details."""
    columns = ["TYPE", "CLUSTER-IP", "EXTERNAL-IP", "PORT(S)", "AGE"]
    print_header("Services", columns, include_namespace=all_namespaces)

    for service in service_list:
        name = service.get('metadata', {}).get('name', '')
        namespace = service.get('metadata', {}).get('namespace', '')

        service_type = service.get('spec', {}).get('type', '')
        cluster_ip = service.get('spec', {}).get('clusterIP', '')
        external_ip = '<none>'
        if service_type == 'LoadBalancer':
            ingress = service.get('status', {}).get('loadBalancer', {}).get('ingress', [])
            if ingress:
                # Prioritize IP over hostname
                external_ip = ingress[0].get('ip', ingress[0].get('hostname', '<pending>'))
        elif service_type == 'ExternalName':
            external_ip = service.get('spec', {}).get('externalName', '<none>')

        ports = ", ".join(
            f"{port['port']}:{port.get('nodePort', '')}/{port['protocol']}"
            if 'nodePort' in port else f"{port['port']}/{port['protocol']}"
            for port in service.get('spec', {}).get('ports', [])
        )
        age = calculate_age(service.get('metadata', {}).get('creationTimestamp', ''))

        row_data = []
        if all_namespaces:
            row_data.append(namespace.ljust(20))
        row_data.extend([
            name.ljust(40),
            service_type.ljust(15),
            cluster_ip.ljust(15),
            external_ip.ljust(15),
            ports.ljust(15),
            age.ljust(15)
        ])

        print("  ".join(row_data))

def print_events(event_list, wide_output=False, all_namespaces=False):
    """Prints the event details."""
    columns = ["LAST SEEN", "TYPE", "REASON", "OBJECT", "MESSAGE"]
    print_header("Events", columns, include_namespace=all_namespaces)

    for event in event_list:
        namespace = event.get('metadata', {}).get('namespace', '')
        last_timestamp = event.get('lastTimestamp', event.get('eventTime', ''))
        last_seen = calculate_age(last_timestamp) if last_timestamp else "N/A"
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
            row_data.append(namespace.ljust(20))
        row_data.extend([
            obj_name.ljust(40),
            last_seen.ljust(15),
            event_type.ljust(15),
            reason.ljust(15),
            obj_str.ljust(15),
            message
        ])

        print("  ".join(row_data))

def print_replicasets(replicaset_list, wide_output=False, all_namespaces=False):
    """Prints the replicaset details."""
    columns = ["DESIRED", "CURRENT", "READY", "AGE"]
    print_header("ReplicaSets", columns, include_namespace=all_namespaces)

    for rs in replicaset_list:
        name = rs.get('metadata', {}).get('name', '')
        namespace = rs.get('metadata', {}).get('namespace', '')

        desired = rs.get('spec', {}).get('replicas', 0)
        current = rs.get('status', {}).get('replicas', 0)
        ready = rs.get('status', {}).get('readyReplicas', 0)
        age = calculate_age(rs.get('metadata', {}).get('creationTimestamp', ''))

        row_data = []
        if all_namespaces:
            row_data.append(namespace.ljust(20))
        row_data.extend([
            name.ljust(40),
            str(desired).ljust(15),
            str(current).ljust(15),
            str(ready).ljust(15),
            age.ljust(15)
        ])

        print("  ".join(row_data))

def print_jobs(job_list, wide_output=False, all_namespaces=False):
    """Prints the job details."""
    columns = ["COMPLETIONS", "DURATION", "AGE"]
    print_header("Jobs", columns, include_namespace=all_namespaces)

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
                pass # duration remains N/A

        age = calculate_age(job.get('metadata', {}).get('creationTimestamp', ''))

        row_data = []
        if all_namespaces:
            row_data.append(namespace.ljust(20))
        row_data.extend([
            name.ljust(40),
            str(completions).ljust(15),
            duration.ljust(15),
            age.ljust(15)
        ])

        print("  ".join(row_data))

def print_cronjobs(cronjob_list, wide_output=False, all_namespaces=False):
    """Prints the cronjob details."""
    columns = ["SCHEDULE", "SUSPEND", "LAST SCHEDULE", "AGE"]
    print_header("CronJobs", columns, include_namespace=all_namespaces)

    for cj in cronjob_list:
        name = cj.get('metadata', {}).get('name', '')
        namespace = cj.get('metadata', {}).get('namespace', '')

        schedule = cj.get('spec', {}).get('schedule', '')
        suspend = cj.get('spec', {}).get('suspend', False)
        last_schedule_time = cj.get('status', {}).get('lastScheduleTime')
        last_schedule = calculate_age(last_schedule_time) if last_schedule_time else '<none>'
        age = calculate_age(cj.get('metadata', {}).get('creationTimestamp', ''))

        row_data = []
        if all_namespaces:
            row_data.append(namespace.ljust(20))
        row_data.extend([
            name.ljust(40),
            schedule.ljust(15),
            str(suspend).ljust(15),
            last_schedule.ljust(15),
            age.ljust(15)
        ])

        print("  ".join(row_data))

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
    """Parses a YAML file and returns a list of resource items."""
    if not os.path.exists(file_path):
        return []

    with open(file_path, 'r') as file:
        try:
            parsed_output = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file {file_path}: {e}", file=sys.stderr)
            return []

    if parsed_output is None:
        return []

    items = []
    if 'items' in parsed_output:
        items = parsed_output['items']
    elif isinstance(parsed_output, dict) and 'apiVersion' in parsed_output and 'kind' in parsed_output:
        items = [parsed_output]
    elif isinstance(parsed_output, list):
        items = parsed_output

    return items

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

def main():
    # Check if running from cluster-dump directory
    cwd = os.getcwd()
    if not cwd.endswith('cluster-dump'):
        print("Error: This command must be run from within a 'cluster-dump' directory")
        print(f"Current directory: {cwd}")
        print("Please navigate to the cluster-dump directory and try again")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Platform9 Cluster Dump Inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""\
        Examples:
          # List all events across all namespaces
          pf9dumpctl events -A

          # List pods in specific namespace with wide output
          pf9dumpctl pods -n kube-system -o wide

          # View logs for a specific pod
          pf9dumpctl logs -n in-pa-pune --pod-name percona-db-pxc-db-haproxy-2

          # List all available namespaces
          pf9dumpctl --list-namespaces

          # List all available resource types
          pf9dumpctl --list-resources

        Supported Resource Types:
          pods, deployments, statefulsets, daemonsets, replicasets,
          services, events, jobs, cronjobs, nodes, logs
        """))

    parser.add_argument("resource_type", nargs='?', choices=[
        "pods", "deployments", "statefulsets", "daemonsets", "replicasets",
        "services", "events", "jobs", "cronjobs", "nodes", "logs"
    ], help="The type of Kubernetes resource to query")
    parser.add_argument("-n", "--namespace", help="Filter by namespace")
    parser.add_argument("--all-namespaces", "-A", action="store_true",
                       help="Query all namespaces")
    parser.add_argument("-o", "--output", choices=["wide"],
                       help="Output format (wide for extended information)")
    parser.add_argument("--pod-name", help="Specify pod name for logs")
    parser.add_argument("--list-resources", action="store_true",
                       help="List all available resource types")
    parser.add_argument("--list-namespaces", action="store_true",
                       help="List all available namespaces")
    parser.add_argument("--version", action="version",
                       version=f"%(prog)s {VERSION}",
                       help="Show version and exit")

    args = parser.parse_args()

    # Validate arguments
    if args.resource_type == "logs" and not (args.namespace and args.pod_name):
        print("Error: For 'logs' resource type, both --namespace and --pod-name are required", file=sys.stderr)
        sys.exit(1)

    if not args.resource_type and not (args.list_resources or args.list_namespaces):
        parser.print_help()
        sys.exit(1)

    base_dump_path = os.getcwd()

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
    }

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

    if args.all_namespaces:
        # Print all collected resources at once with namespace column
        if all_collected_resources:
            resource_printer(all_collected_resources,
                           wide_output=(args.output == "wide"),
                           all_namespaces=True)
        else:
            print(f"No {resource_display_name} found across all namespaces.")
    else:
        # Print resources for the single specified namespace
        if all_collected_resources:
            print(f"\n--- Namespace: {args.namespace} ---")
            resource_printer(all_collected_resources,
                          wide_output=(args.output == "wide"),
                          all_namespaces=False)
        else:
            print(f"No {resource_display_name} found in namespace '{args.namespace}'.")

if __name__ == "__main__":
    main()