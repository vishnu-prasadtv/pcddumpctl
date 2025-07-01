# 🚀 pf9dumpctl - Platform9 Cluster Dump Inspector

`pf9dumpctl` is a lightweight Python CLI tool that simulates `kubectl`-like interactions with offline Platform9 Kubernetes cluster dump files.

---

## ✨ Features

- Inspect Kubernetes resources from offline cluster dumps
- Filter by namespace or across all namespaces
- Supports multiple output formats (`wide`, `yaml`)
- View pod logs
- Describe individual resources
- Familiar `kubectl`-style CLI experience

---

## 📦 Installation

### 1. Clone the GitHub Repository

```bash
git clone https://github.com/vishnu-prasadtv/pf9dumpctl.git
cd pf9dumpctl
```

### 2. Set Up Python Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv pf9env

# Activate the virtual environment
source pf9env/bin/activate
```

### 3. Install Required Python Modules

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

*Contents of `requirements.txt`:*
```
pyyaml>=5.3.1
tabulate>=0.8.9
```

### 4. Make the Script Executable

```bash
chmod +x pf9dumpctl.py
```

### 5. Copy the Script to a System-Wide Path

```bash
sudo cp pf9dumpctl.py /usr/local/bin/pf9dumpctl
```

### 6. (Optional) Add an Alias for Easier Access

Add the following to your shell config (`~/.bashrc`, `~/.zshrc`, etc.):


```bash
echo "alias pc='python3 /usr/local/bin/pf9dumpctl'" >> ~/.bashrc
source ~/.bashrc
```

### 7. Set the Cluster Dump Path

```bash
export CLUSTER_DUMP_PATH=/path/to/your/cluster-dump
```

---

## 🛠️ Usage

```bash
pf9dumpctl [command] [options]
```

---

### ✅ Commands

| Command     | Description                          |
|-------------|--------------------------------------|
| `get`       | List Kubernetes resources            |
| `describe`  | Show detailed info about a resource  |
| `logs`      | View pod logs                        |

### 🔍 Supported Resource Types

For `get` and `describe` commands:
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
- `namespaces`

### ⚙️ Options

| Option                  | Description                                |
|-------------------------|--------------------------------------------|
| `-n`, `--namespace`     | Specify the namespace                      |
| `-A`, `--all-namespaces`| Show resources across all namespaces       |
| `-o`, `--output`        | Output format (`wide`, `yaml`)             |
| `--version`             | Show tool version                          |

---

## 🔧 Examples

```bash
# List all pods in kube-system
pf9dumpctl get pods -n kube-system

# Get deployments with wide output
pf9dumpctl get deployments -o wide

# Get outputs with -o yaml
pf9dumpctl get pods my-pod-name -n my-namespace -o yaml

# Describe a specific deployment
pf9dumpctl describe deployment my-deploy -n my-namespace

# View logs for a pod
pf9dumpctl logs -n kube-system my-pod-name

# Get all events across namespaces
pf9dumpctl get events -A
```

---

## 📋 Requirements

- Python 3.6+
- `pyyaml`
- `tabulate`

---

## 👥 Maintainers

- **Abhijith Ajayan**
- **Vishnu Prasad**
