
## Pre-requisites

- Make sure to execute `pf9dumpctl` from the `cluster-dump` directory.

## Usage

```bash
pf9dumpctl --help
```

Output:

```
usage: pf9dumpctl [-h] [-n NAMESPACE] [--all-namespaces] [-o {wide}] [--pod-name POD_NAME] [--list-resources] [--list-namespaces] [--version]
                   [{pods,deployments,statefulsets,daemonsets,replicasets,services,events,jobs,cronjobs,nodes,logs}]

Platform9 Cluster Dump Inspector

positional arguments:
  {pods,deployments,statefulsets,daemonsets,replicasets,services,events,jobs,cronjobs,nodes,logs}
                        The type of Kubernetes resource to query

options:
  -h, --help            show this help message and exit
  -n, --namespace NAMESPACE
                        Filter by namespace
  --all-namespaces, -A  Query all namespaces
  -o, --output {wide}   Output format (wide for extended information)
  --pod-name POD_NAME   Specify pod name for logs
  --list-resources      List all available resource types
  --list-namespaces     List all available namespaces
  --version             Show version and exit

Examples:
  # List all events across all namespaces
  pf9dumpctl events -A

  # List pods in specific namespace with wide output
  pf9dumpctl pods -n kube-system -o wide

  # View logs for a specific pod
  pf9dumpctl logs -n <namespace> --pod-name percona-db-pxc-db-haproxy-2

  # List all available namespaces
  pf9dumpctl --list-namespaces

  # List all available resource types
  pf9dumpctl --list-resources

Supported Resource Types:
  pods, deployments, statefulsets, daemonsets, replicasets,
  services, events, jobs, cronjobs, nodes, logs
```
