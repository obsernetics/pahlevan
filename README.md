
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

<p align="center"><b>eBPF-powered Kubernetes Security Operator</b><br/>Adaptive runtime protection & policy enforcement</p>

## Why Pahlevan?

Kubernetes workloads face **runtime attacks** that bypass perimeter defenses.  
Pahlevan delivers **adaptive, kernel-level protection** by learning normal workload behavior and enforcing policies proactively.

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
  <li>Kubernetes <b>v1.24+</b></li>
  <li>Linux Kernel <b>4.18+</b> with eBPF enabled</li>
  <li>Minimum: <b>256MB memory</b>, <b>100m CPU</b></li>
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
