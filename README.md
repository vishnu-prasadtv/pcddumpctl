# 🚀 pcddumpctl - Platform9 Cluster Dump Inspector

`pcddumpctl` is a lightweight Python CLI tool that simulates `kubectl`-like interactions with offline Platform9 Kubernetes cluster dump files.

---

## ✨ Features

- Inspect Kubernetes resources from offline cluster dumps
- Filter by namespace or across all namespaces
- Supports multiple output formats (`wide`, `yaml`)
- View pod logs
- Familiar `kubectl`-style CLI experience

---

# 📦 Installation

## Automated steps to configure:
```
bash pcddumctl-start.sh
```

## Manual steps to configure:
### 1. Clone the GitHub Repository

```bash
git clone https://github.com/vishnu-prasadtv/pcddumpctl.git
cd pcddumpctl
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
echo "pyyaml>=5.3.1
tabulate>=0.8.9"
pip install -r requirements.txt
```

### 4. Make the Script Executable

```bash
chmod +x pcddumpctl.py
```

### 5. Copy the Script to a System-Wide Path

```bash
sudo cp pcddumpctl.py /usr/local/bin/pcddumpctl
```

### 6. (Optional) Add an Alias for Easier Access

Add the following to your shell config (`~/.bashrc`, `~/.zshrc`, etc.):


```bash
echo "alias pc='python3 /usr/local/bin/pcddumpctl'" >> ~/.bashrc
source ~/.bashrc
```

### 7. Set the Cluster Dump Path

```bash
export CLUSTER_DUMP_PATH=/path/to/your/pcd-dump
```

Note: Ensure the path `/path/to/your/pcd-dump` has the related namespace folders present.
Example:
```
$ ls /path/to/your/pcd-dump
nodes.yaml    ns1-folder    ns2-folder    ns3-folder
ns4-folder    ns5-folder    ns6-folder    ns7-folder
```

---

## 🛠️ Usage

```bash
pcddumpctl [command] [options]
```

---

### ✅ Commands

```
Commands:
  get            Get resources
  describe       Describe a resource
  logs           Show pod logs
  top            Show resource usage metrics
  api-resources  List resource types (like kubectl api-resources)
```

### 🔍 Supported Resource Types

```
NAME                            SHORTNAMES                   APIGROUP                     NAMESPACED KIND
pods                            po,pod                                                    true       Pod
deployments                     deploy,deployment            apps                         true       Deployment
statefulsets                    statefulset,sts              apps                         true       StatefulSet
daemonsets                      daemonset,ds                 apps                         true       DaemonSet
replicasets                     replicaset,rs                apps                         true       ReplicaSet
services                        service,svc                                               true       Service
events                          ev,event                                                  true       Event
jobs                            job                          batch                        true       Job
cronjobs                        cj,cronjob                   batch                        true       CronJob
secrets                         secret                                                    true       Secret
configmaps                      cm,configmap                                              true       ConfigMap
endpoints                       ep                                                        true       Endpoints
persistentvolumeclaims          persistentvolumeclaim,pvc                                 true       PersistentVolumeClaim
resourcequotas                  quota,resourcequota                                       true       ResourceQuota
networkpolicies                 netpol,networkpolicy         networking.k8s.io            true       NetworkPolicy
poddisruptionbudgets            pdb,poddisruptionbudget      policy                       true       PodDisruptionBudget
rolebindings                    rolebinding                  rbac.authorization.k8s.io    true       RoleBinding
roles                           role                         rbac.authorization.k8s.io    true       Role
ingresses                       ing,ingress                  networking.k8s.io            true       Ingress
persistentvolumes               persistentvolume,pv                                       false      PersistentVolume
storageclasses                  sc,storageclass              storage.k8s.io               false      StorageClass
ingressclasses                                               networking.k8s.io            false      IngressClass
clusterrolebindings             clusterrolebinding           rbac.authorization.k8s.io    false      ClusterRoleBinding
clusterroles                    clusterrole                  rbac.authorization.k8s.io    false      ClusterRole
nodes                           no,node                                                   false      Node
csidrivers                                                   storage.k8s.io               false      CSIDriver
csinodes                                                     storage.k8s.io               false      CSINode
csistoragecapacities                                         storage.k8s.io               false      CSIStorageCapacity
customresourcedefinitions       crd,customresourcedefinition apiextensions.k8s.io         false      CustomResourceDefinition
priorityclasses                                              scheduling.k8s.io            false      PriorityClass
runtimeclasses                                               node.k8s.io                  false      RuntimeClass
volumeattachments                                            storage.k8s.io               false      VolumeAttachment
mutatingwebhookconfigurations                                admissionregistration.k8s.io false      MutatingWebhookConfiguration
validatingwebhookconfigurations                              admissionregistration.k8s.io false      ValidatingWebhookConfiguration
namespaces                      namespace,ns                                              false      Namespace
```

### ⚙️ Options

```
Positional arguments:
      resource
      resource_names        Name(s) of the resource(s) (optional, multiple allowed)

Options:
      -h, --help            show this help message and exit
      -n, --namespace NAMESPACE
                        Namespace to filter by (if applicable)
      -A, --all-namespaces  List across all namespaces
      -b, --basepath BASEPATH
                        Base path to cluster-dump directory
      -oyaml, --oyaml       Output full yaml
      -owide, --owide       Wide output (extra columns)
      --show-labels         Show labels column
```

---

## 🔧 Examples

```bash
Commands 
        pcddumpctl get <Namespace-scoped-resource> -n <NS>  | head 
        pcddumpctl get <Namespace-scoped-resource> -n <NS>  -owide  | head 
        pcddumpctl get <Namespace-scoped-resource> -n <NS>  --show-labels  | head 
        pcddumpctl get <Namespace-scoped-resource> -A | head 
        pcddumpctl get <Namespace-scoped-resource> -A -owide| head 
        pcddumpctl get <Namespace-scoped-resource> -A --show-labels| head 

        pcddumpctl get <Cluster-scoped-resource>    | head 
        pcddumpctl get <Cluster-scoped-rresource> -owide  | head 
        pcddumpctl get <Cluster-scoped-rresource> --show-labels  | head 


        pcddumpctl top nodes  | head 
        pcddumpctl top pods -n <NS>  | head 
        pcddumpctl top pods -A   | head 

        pcddumpctl describe  <Namespace-scoped-resource> -n <NS>    | head 
        pcddumpctl describe <Cluster-scoped-resource>  | head 


        pcddumpctl get  <Namespace-scoped-resource> -n <NS>   -oyaml  | head 
        pcddumpctl get   <Cluster-scoped-resource>   -oyaml     | head 


        pcddumpctl logs -n <NS> <pod-name> | head 

    
        pcddumpctl get events -n <NS>  | head 
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
