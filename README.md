
<p align="center">
  <a href="https://goreportcard.com/report/github.com/obsernetics/pahlevan">
    <img src="https://goreportcard.com/badge/github.com/obsernetics/pahlevan" alt="Go Report Card" />
  </a>
  <a href="https://opensource.org/licenses/Apache-2.0">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License" />
  </a>
  <a href="https://github.com/obsernetics/pahlevan/actions/workflows/ci.yml">
    <img src="https://github.com/obsernetics/pahlevan/workflows/CI/badge.svg" alt="CI Status" />
  </a>
</p>

<p align="center"><b>eBPF-powered Kubernetes runtime security</b><br/>Adaptive, self-learning protection with in-kernel enforcement</p>

## Why Pahlevan?

Kubernetes workloads face **runtime attacks** that bypass perimeter defenses.
Pahlevan delivers **adaptive, kernel-level protection** by learning each workload's
normal behavior and then enforcing it proactively — no hand-written rules.

Unlike alert-only or observability tools, Pahlevan **blocks** in-kernel (LSM BPF +
seccomp) the moment a workload steps outside its learned baseline, and **self-heals**
by rolling back a policy that disrupts a workload.

### Architecture

Pahlevan runs as two components (like Falco and Tetragon, it must instrument every node):

- **Agent** — a privileged **DaemonSet** on every node. It owns the eBPF data plane:
  load/attach programs, learn per-container baselines, and enforce locally in-kernel.
- **Operator** — a leader-elected **Deployment** control plane. It needs no host access
  and runs in a **user namespace** (`hostUsers: false`); it handles policy lifecycle,
  cluster-wide status aggregation, and CEL admission policy.

<table>
<thead>
<tr>
<th>Solution</th>
<th>Focus</th>
<th>Learns Behavior</th>
<th>Enforcement</th>
<th>Coverage</th>
</tr>
</thead>
<tbody>
<tr>
<td><b>Pahlevan</b></td>
<td>Adaptive policy operator</td>
<td>Auto-learning</td>
<td>Proactive blocking</td>
<td>Syscalls • Files • Network • Processes</td>
</tr>
<tr>
<td>Falco</td>
<td>Threat detection</td>
<td>Manual rules</td>
<td>Alerts only</td>
<td>Runtime monitoring</td>
</tr>
<tr>
<td>Tetragon</td>
<td>Observability</td>
<td>Manual rules</td>
<td>Partial</td>
<td>Kernel tracing</td>
</tr>
<tr>
<td>Cilium</td>
<td>Network security</td>
<td>Static rules</td>
<td>Network only</td>
<td>L3–L7 traffic</td>
</tr>
</tbody>
</table>

---

## Features

- **Runtime Monitoring** – Syscalls, file I/O, network, processes (via eBPF)
- **Adaptive Learning** – Automatic workload profiling & policy generation
- **Policy Enforcement** – CRD-based, monitor or block mode
- **Self-Healing** – Auto rollback if policies disrupt workloads
- **Kubernetes Native** – Operator pattern & CRD integration  


## Quick Start

```bash
# Install
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml

# Create policy
cat <<EOF | kubectl apply -f -
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: nginx-security
spec:
  selector:
    matchLabels:
      app: nginx
  learning:
    enabled: true
    duration: 5m
  enforcement:
    mode: "monitor"
  selfHealing:
    enabled: true
EOF

# Deploy workload
kubectl create deployment nginx --image=nginx
kubectl label deployment nginx app=nginx

# Monitor
kubectl get pahlevanpolicy nginx-security -w
```

<h2 id="requirements">Requirements</h2>

<ul>
  <li>Kubernetes <b>v1.24+</b> (user-namespace operator needs <b>v1.30+</b>)</li>
  <li>Linux Kernel <b>5.8+</b> for monitoring (CO-RE, ring buffer, CAP_BPF)</li>
  <li>Kernel <b>5.7+ with <code>CONFIG_BPF_LSM</code> and <code>lsm=bpf</code></b> for in-kernel enforcement (monitor-only mode works without it)</li>
  <li>Minimum: <b>256MB memory</b>, <b>100m CPU</b> per node agent</li>
</ul>


<h2 id="installation">Installation</h2>

<p><b>Helm (recommended):</b></p>

<pre><code>helm repo add pahlevan https://obsernetics.github.io/pahlevan-charts
helm install pahlevan pahlevan/pahlevan-operator -n pahlevan-system --create-namespace
</code></pre>


<h2 id="license">License</h2>

<p>
  Licensed under the 
  <a href="https://opensource.org/licenses/Apache-2.0">Apache License 2.0</a>.
</p>
