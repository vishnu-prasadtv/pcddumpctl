```markdown
# pf9dumpctl - Platform9 Cluster Dump Inspector

A Python utility for inspecting Platform9 Kubernetes cluster dump files.

## Features

- View Kubernetes resources from cluster dump files
- Filter by namespace or resource type
- Output in wide format or YAML
- View pod logs
- Describe specific resources

## Installation

pip install pyyaml
chmod +x pf9dumpctl.py
sudo cp pf9dumpctl.py /usr/local/bin/pf9dumpctl
```

## Usage

```
pf9dumpctl [command] [options]
```

### Commands

| Command    | Description                          |
|------------|--------------------------------------|
| `get`      | List Kubernetes resources            |
| `describe` | Show detailed info about a resource |
| `logs`     | View pod logs                        |

### Resource Types

Supported resource types for `get` and `describe` commands:
- `pods`
- `deployments`
- `statefulsets`
- `daemonsets`
- `replicasets`
- `services`
- `events`
- `jobs`
- `cronjobs`
- `nodes`

### Options

| Option              | Description                          |
|---------------------|--------------------------------------|
| `-n, --namespace`   | Filter by namespace                  |
| `-A, --all-namespaces` | Show resources from all namespaces |
| `-o, --output`      | Output format (wide, yaml)           |
| `--list-resources`  | List available resource types        |
| `--list-namespaces` | List available namespaces            |
| `--version`         | Show version                         |

## Examples

```
# List all pods in kube-system namespace
pf9dumpctl get pods -n kube-system

# List deployments with wide output
pf9dumpctl get deployments -o wide

# View logs for a specific pod
pf9dumpctl logs -n my-namespace my-pod

# Describe a deployment
pf9dumpctl describe deployment my-deployment -n my-namespace

# List all events across all namespaces
pf9dumpctl get events -A
```

## Requirements

- Python 3.6+
- PyYAML

## Known Issues

- Logs functionality requires logs.txt files in pod directories
- Some edge cases in timestamp parsing may occur
- Wide output formatting may not align perfectly in all terminals

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
