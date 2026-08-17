#!/usr/bin/env bash
#
# run.sh - Reproducible measurement of what Pahlevan detects, what it blocks,
# and what it costs to run.
#
# Runs INSIDE the kernel-isolated VM (hack/vm/). eBPF is never loaded on the host.
#
# Two passes against the same workload and the same attack scenarios: a control
# pass with no agent installed, and a Pahlevan pass. The control pass is what
# makes the cost figure meaningful - CPU and memory are only interesting as a
# difference from an unwatched node, and detection counts are only interesting
# once you know the scenarios actually executed with nothing to stop them.
#
# Everything this produces is a real measurement; see docs/benchmarks/ for
# recorded runs.
#
# Usage (from the repo root, on the host):
#   hack/vm/up.sh                      # boot the VM (kernel 6.8, bpf LSM active)
#   test/benchmark/run.sh setup        # k3s + helm + the nginx:1.27 target
#   test/benchmark/run.sh control      # the same scenarios with no agent at all
#   test/benchmark/run.sh pahlevan     # build+deploy Pahlevan, learn, enforce, attack
#   test/benchmark/run.sh all          # setup + control + pahlevan
#
# Artifacts land in ${SCRATCH}/results/<tool>/ on the HOST:
#   scenarios.txt  raw SCENARIO lines from the in-pod runner (with timestamps)
#   signals.raw    the tool's own signal stream for the run window
#   matrix.txt     per-scenario matrix produced by correlate.py
#   matrix.json    the same, machine readable
#   resources.txt  cgroup v2 CPU/memory (and, for Pahlevan, BPF map memlock)
#   meta.txt       versions, cgroup ids, enforcement state, exec probe
#
# How scenarios are executed (this changed after the 2026-08-14 run):
# a resident bash runner is started inside the target pod while the tool under
# test is still learning/observing, and it drives every scenario using only
# builtins. See test/benchmark/pod-runner.sh for why, and test/benchmark/README.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH_DIR="${REPO_ROOT}/test/benchmark"
VM_RUN="${REPO_ROOT}/hack/vm/run.sh"
VM_CP="${REPO_ROOT}/hack/vm/cp.sh"
SCRATCH="${SCRATCH:-/tmp/pahlevan-bench}"
RESULTS="${SCRATCH}/results"
GAP="${BENCH_GAP:-3}"
mkdir -p "${SCRATCH}" "${RESULTS}"

log() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

# vms - run a script (read from stdin) inside the VM. Using a file instead of a
# quoted one-liner keeps quoting sane for anything non-trivial.
vms() {
  local name="${1:-vmscript}"
  local tmp="${SCRATCH}/${name}.sh"
  cat >"${tmp}"
  "${VM_CP}" "${tmp}" "/tmp/${name}.sh" >/dev/null
  "${VM_RUN}" "bash /tmp/${name}.sh"
}

# vm - run a short one-liner inside the VM.
vm() { "${VM_RUN}" "$*"; }

# --------------------------------------------------------------------------
# 0. Cluster + tooling (idempotent)
# --------------------------------------------------------------------------
setup_cluster() {
  log "Install k3s + helm in the VM (idempotent)"
  vms setup-cluster <<'EOF'
set -eu
command -v k3s >/dev/null 2>&1 || curl -sfL https://get.k3s.io | sudo INSTALL_K3S_EXEC="--write-kubeconfig-mode=644 --disable=traefik --disable=metrics-server" sh -
command -v helm >/dev/null 2>&1 || (curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash)
sudo kubectl wait --for=condition=Ready node --all --timeout=180s
EOF
}

# --------------------------------------------------------------------------
# 1. Benign target workload (the thing all three tools "protect")
# --------------------------------------------------------------------------
deploy_target() {
  log "Deploy benign target workload (nginx:1.27, Debian -> has bash/curl for scenarios)"
  vms deploy-target <<'EOF'
set -eu
cat > /tmp/target.yaml <<'YAML'
apiVersion: v1
kind: Namespace
metadata: {name: bench}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: target, namespace: bench, labels: {app: target}}
spec:
  replicas: 1
  selector: {matchLabels: {app: target}}
  template:
    metadata: {labels: {app: target, pahlevan: protected}}
    spec:
      containers:
      - name: app
        image: nginx:1.27
        ports: [{containerPort: 80}]
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 200m, memory: 64Mi}}
YAML
sudo kubectl apply -f /tmp/target.yaml
sudo kubectl -n bench rollout status deploy/target --timeout=180s
EOF
}

# Copy the scenario scripts + the in-pod runner into the VM. Idempotent.
stage_scenarios() {
  log "Stage scenarios + pod runner into the VM"
  vm 'rm -rf /tmp/bench-scenarios /tmp/pod-runner.sh /tmp/correlate.py'
  "${VM_CP}" -r "${BENCH_DIR}/scenarios" /tmp/bench-scenarios >/dev/null
  "${VM_CP}" "${BENCH_DIR}/pod-runner.sh" /tmp/pod-runner.sh >/dev/null
}

# --------------------------------------------------------------------------
# 2. In-pod runner lifecycle
# --------------------------------------------------------------------------
# target_facts - write pod name, container id, host pid and cgroup ids to
# /tmp/bench-facts in the VM, and echo them here.
target_facts() {
  vms target-facts <<'EOF'
set -eu
POD=$(sudo kubectl -n bench get pod -l app=target -o jsonpath='{.items[0].metadata.name}')
UID_=$(sudo kubectl -n bench get pod "$POD" -o jsonpath='{.metadata.uid}')
CID=$(sudo kubectl -n bench get pod "$POD" -o jsonpath='{.status.containerStatuses[0].containerID}')
CID=${CID#*://}
PID=$(sudo k3s crictl inspect "$CID" | python3 -c 'import sys,json;print(json.load(sys.stdin)["info"]["pid"])')
U=$(printf '%s' "$UID_" | tr - _)
CGIDS=""
for d in $(sudo find /sys/fs/cgroup -type d -path "*pod${U}*" 2>/dev/null); do
  CGIDS="${CGIDS}$(stat -c %i "$d"),"
done
CGIDS=${CGIDS%,}
{
  echo "POD=$POD"
  echo "PODUID=$UID_"
  echo "CID=$CID"
  echo "PID=$PID"
  echo "CGIDS=$CGIDS"
} | sudo tee /tmp/bench-facts >/dev/null
cat /tmp/bench-facts
EOF
}

# start_runner - stage /tmp/bench inside the target container (through
# /proc/<pid>/root, from the node) and start the resident runner. Must be called
# while the tool under test is still learning/observing.
start_runner() {
  log "Start the resident in-pod runner (while the tool is still learning/observing)"
  vms start-runner <<EOF
set -eu
. /tmp/bench-facts
R=/proc/\$PID/root
sudo rm -rf "\$R/tmp/bench"
sudo mkdir -p "\$R/tmp/bench"
sudo cp -r /tmp/bench-scenarios "\$R/tmp/bench/scenarios"
sudo cp /tmp/pod-runner.sh "\$R/tmp/bench/pod-runner.sh"
sudo chmod -R a+rX "\$R/tmp/bench"
sudo kubectl -n bench exec "\$POD" -- bash -c 'nohup setsid bash /tmp/bench/pod-runner.sh ${GAP} </dev/null >/tmp/bench/runner.log 2>&1 & sleep 2; echo started'
for i in \$(seq 1 30); do
  if sudo grep -q 'RUNNER ready' "\$R/tmp/bench/out.txt" 2>/dev/null; then echo "runner ready"; break; fi
  sleep 1
done
sudo cat "\$R/tmp/bench/out.txt"
EOF
}

# arm_and_wait - trigger the run and block until the runner reports done.
arm_and_wait() {
  log "Arm the in-pod runner and wait for the suite to finish"
  vms arm-and-wait <<'EOF'
set -eu
. /tmp/bench-facts
R=/proc/$PID/root
date -u +'RUN_START=%Y-%m-%dT%H:%M:%SZ' | sudo tee /tmp/bench-window >/dev/null
echo go | sudo tee "$R/tmp/bench/trigger" >/dev/null
for i in $(seq 1 400); do
  if sudo grep -q 'RUNNER done' "$R/tmp/bench/out.txt" 2>/dev/null; then break; fi
  if sudo grep -q 'RUNNER trigger-timeout' "$R/tmp/bench/out.txt" 2>/dev/null; then
    echo "RUNNER TIMED OUT WAITING FOR TRIGGER" >&2; break
  fi
  sleep 2
done
date -u +'RUN_END=%Y-%m-%dT%H:%M:%SZ' | sudo tee -a /tmp/bench-window >/dev/null
sudo cp "$R/tmp/bench/out.txt" /tmp/bench-out.txt
sudo chmod a+r /tmp/bench-out.txt
cat /tmp/bench-window
grep -c '^SCENARIO' /tmp/bench-out.txt || true
EOF
}

fetch_scenarios() {
  local tool="$1"
  mkdir -p "${RESULTS}/${tool}"
  vm 'cat /tmp/bench-out.txt' >"${RESULTS}/${tool}/scenarios.txt"
  vm 'cat /tmp/bench-window' >"${RESULTS}/${tool}/window.txt"
  vm 'cat /tmp/bench-facts' >"${RESULTS}/${tool}/facts.txt"
}

# --------------------------------------------------------------------------
# 3. Resource measurement (cgroup v2, not kubectl top)
# --------------------------------------------------------------------------
# measure_agent <selector> <namespace> <label>
measure_agent() {
  local sel="$1" ns="$2" label="$3"
  vms measure-agent <<EOF
set -eu
echo "--- ${label} ---"
AUID=\$(sudo kubectl -n ${ns} get pod -l ${sel} -o jsonpath='{.items[0].metadata.uid}')
U=\$(printf '%s' "\$AUID" | tr - _)
PS=\$(sudo find /sys/fs/cgroup -type d -path "*pod\${U}*" 2>/dev/null | grep -v 'cri-containerd' | head -1)
echo "cgroup: \$PS"
echo "memory.current: \$(cat \$PS/memory.current) bytes"
echo "memory.peak: \$(cat \$PS/memory.peak 2>/dev/null || echo n/a)"
sed -n '1,6p' \$PS/memory.stat
u1=\$(awk '/usage_usec/{print \$2}' \$PS/cpu.stat); t1=\$(date +%s%N)
sleep 30
u2=\$(awk '/usage_usec/{print \$2}' \$PS/cpu.stat); t2=\$(date +%s%N)
awk -v a=\$u1 -v b=\$u2 -v c=\$t1 -v d=\$t2 'BEGIN{printf "cpu_idle_pct_of_one_core: %.2f\n",(b-a)*1000*100/(d-c)}'
echo "memory.current_after_idle: \$(cat \$PS/memory.current) bytes"
# Under load: a tight request loop against the target for 30s.
PODIP=\$(sudo kubectl -n bench get pod -l app=target -o jsonpath='{.items[0].status.podIP}')
u1=\$(awk '/usage_usec/{print \$2}' \$PS/cpu.stat); t1=\$(date +%s%N)
end=\$((SECONDS+30)); while [ \$SECONDS -lt \$end ]; do curl -s -o /dev/null "http://\$PODIP/" || true; done
u2=\$(awk '/usage_usec/{print \$2}' \$PS/cpu.stat); t2=\$(date +%s%N)
awk -v a=\$u1 -v b=\$u2 -v c=\$t1 -v d=\$t2 'BEGIN{printf "cpu_load_pct_of_one_core: %.2f\n",(b-a)*1000*100/(d-c)}'
echo "memory.current_after_load: \$(cat \$PS/memory.current) bytes"
EOF
}

# measure_bpf_maps - sum bytes_memlock for Pahlevan's maps, from bpftool. This is
# the kernel-side half of the memory story; the rest is the Go runtime.
measure_bpf_maps() {
  vms measure-bpf <<'EOF'
set -eu
cat > /tmp/bpfsum.py <<'PY'
import json, sys
ours = {"events","file_events","network_events","exec_events","cap_events",
        "syscall_seen","file_allowed","network_allowed","exec_allowed","cap_allowed",
        "file_mode","network_mode","exec_mode","cap_mode","config_map","file_config"}
maps = json.load(sys.stdin)
total = 0
rows = []
for m in maps:
    if m.get("name") in ours:
        b = m.get("bytes_memlock", 0)
        total += b
        rows.append((m["name"], m.get("max_entries"), b))
for n, e, b in sorted(rows):
    print("  %-16s max_entries=%-8s memlock=%9.2f KiB" % (n, e, b/1024))
print("BPF_MAP_MEMLOCK_TOTAL_BYTES=%d" % total)
print("BPF_MAP_MEMLOCK_TOTAL_MIB=%.2f" % (total/1048576))
print("BPF_MAP_COUNT=%d" % len(rows))
PY
sudo bpftool -j map show > /tmp/bpfmaps.json
python3 /tmp/bpfsum.py < /tmp/bpfmaps.json
EOF
}

# --------------------------------------------------------------------------
# 3b. CONTROL: no security tool installed at all.
# --------------------------------------------------------------------------
# Establishes which scenarios succeed on a bare cluster, so a later "blocked"
# can be attributed to the tool rather than to the image lacking a binary or to
# an unroutable destination.
run_control() {
  mkdir -p "${RESULTS}/control"
  log "CONTROL: no security tool installed; baseline outcome of every scenario"
  stage_scenarios
  target_facts >"${RESULTS}/control/facts.txt"
  start_runner
  sleep 5
  arm_and_wait
  fetch_scenarios control
  : >"${RESULTS}/control/signals.raw"
  cat "${RESULTS}/control/scenarios.txt"
}

# --------------------------------------------------------------------------
# 4. PAHLEVAN
# --------------------------------------------------------------------------
build_pahlevan() {
  log "PAHLEVAN: build image from the committed HEAD (host), import into k3s"
  local SRC="${SCRATCH}/src"
  rm -rf "${SRC}"; mkdir -p "${SRC}"
  # git archive, not rsync: the build must be of a pinned committed tree, not of
  # whatever happens to be in the working directory.
  (cd "${REPO_ROOT}" && git rev-parse HEAD >"${SCRATCH}/pinned-sha")
  (cd "${REPO_ROOT}" && git archive HEAD) | tar -x -C "${SRC}"
  # The legacy docker builder does not expand --platform=$BUILDPLATFORM; drop it
  # in the throwaway copy (single-arch build, no functional difference).
  sed -i 's#FROM --platform=$BUILDPLATFORM golang#FROM golang#' "${SRC}/Dockerfile"
  docker build --build-arg TARGETARCH=amd64 -t pahlevan:bench --target runtime "${SRC}"
  docker save pahlevan:bench -o "${SCRATCH}/pahlevan-bench.tar"
  "${VM_CP}" "${SCRATCH}/pahlevan-bench.tar" /tmp/pahlevan-bench.tar >/dev/null
  vm 'sudo k3s ctr images import /tmp/pahlevan-bench.tar'
}

deploy_pahlevan() {
  log "PAHLEVAN: deploy (agent privileged for eBPF/LSM, event export to a host file)"
  "${VM_CP}" "${REPO_ROOT}/install.yaml" /tmp/install.yaml >/dev/null
  vms deploy-pahlevan <<'EOF'
set -eu
# Clean slate: patching an already-patched DaemonSet duplicates the export mount.
sudo kubectl -n bench delete pahlevanpolicy --all --ignore-not-found --grace-period=5 >/dev/null 2>&1 || true
sudo kubectl delete ns pahlevan-system --grace-period=5 --ignore-not-found --wait=true >/dev/null 2>&1 || true
sudo kubectl delete clusterrole pahlevan-agent pahlevan-operator pahlevan-agent-bench-extra --ignore-not-found >/dev/null 2>&1 || true
sudo kubectl delete clusterrolebinding pahlevan-agent pahlevan-operator pahlevan-agent-bench-extra --ignore-not-found >/dev/null 2>&1 || true
sudo kubectl delete crd pahlevanpolicies.policy.pahlevan.io containerprofiles.policy.pahlevan.io attacksurfaces.policy.pahlevan.io --ignore-not-found >/dev/null 2>&1 || true
sudo rm -rf /var/log/pahlevan; sudo mkdir -p /var/log/pahlevan
sed -e "s#ghcr.io/obsernetics/pahlevan:latest#docker.io/library/pahlevan:bench#g" \
    -e "s#imagePullPolicy: IfNotPresent#imagePullPolicy: Never#g" /tmp/install.yaml > /tmp/install-bench.yaml
sed -i "0,/replicas: 2/s//replicas: 1/" /tmp/install-bench.yaml
sed -i "s/          privileged: false/          privileged: true/" /tmp/install-bench.yaml

# WORKAROUND, and a finding in its own right: the committed install.yaml ships a
# PahlevanPolicy CRD the apiserver refuses -
#   spec...properties[selector].properties[namespaceSelector].type:
#   Required value: must not be empty for specified object fields
# Seven schema nodes (selector.namespaceSelector and the networkPolicy peer
# selectors) carry a description but no `type`. Without a type they are not a
# valid structural schema, so `kubectl apply -f install.yaml` fails and Pahlevan
# cannot be installed as shipped. The benchmark patches the copy in /tmp only;
# the repo file is untouched. Report the count so the fix stays visible.
python3 - /tmp/install-bench.yaml <<'PY'
import sys, yaml
path = sys.argv[1]
docs = list(yaml.safe_load_all(open(path)))
fixed = 0
def fix(node):
    global fixed
    if isinstance(node, dict):
        if "properties" in node and isinstance(node["properties"], dict):
            for child in node["properties"].values():
                if isinstance(child, dict) and "type" not in child \
                   and "x-kubernetes-preserve-unknown-fields" not in child:
                    child["type"] = "object"
                    fixed += 1
                fix(child)
        if "items" in node and isinstance(node["items"], dict):
            it = node["items"]
            if "type" not in it and "x-kubernetes-preserve-unknown-fields" not in it:
                it["type"] = "object"
                fixed += 1
            fix(it)
        for k, v in node.items():
            if k not in ("properties", "items"):
                fix(v)
    elif isinstance(node, list):
        for v in node:
            fix(v)
for d in docs:
    fix(d)
with open(path, "w") as fh:
    yaml.safe_dump_all([d for d in docs if d is not None], fh, default_flow_style=False)
print("CRD_SCHEMA_NODES_PATCHED=%d" % fixed)
PY
sudo kubectl apply -f /tmp/install-bench.yaml

# WORKAROUND, and a second finding: the ClusterRole in install.yaml grants the
# agent only policy.pahlevan.io resources plus pods/nodes/events, but the agent's
# controller-runtime manager starts informers for Deployments, DaemonSets,
# StatefulSets, Services and NetworkPolicies. Those informers can never sync, so
# after the 2 minute cache-sync timeout the agent exits 1 with
#   "failed to wait for pahlevanpolicy caches to sync"
# and restarts. It crash-loops on a ~2 minute cycle, and every restart wipes the
# in-memory learned baseline. The extra grant below is read-only and additive; it
# is applied to the cluster only, not to the repo's install.yaml.
cat > /tmp/agent-rbac-workaround.yaml <<'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: pahlevan-agent-bench-extra}
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "statefulsets", "replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["services", "namespaces"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: pahlevan-agent-bench-extra}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: pahlevan-agent-bench-extra}
subjects:
- {kind: ServiceAccount, name: pahlevan-agent, namespace: pahlevan-system}
YAML
sudo kubectl apply -f /tmp/agent-rbac-workaround.yaml

# Event export is the per-scenario signal source. The agent does not write
# events to a file by default, so it is switched on here.
cat > /tmp/export-patch.json <<'JSON'
[
 {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--export-file=/var/log/pahlevan/events.jsonl"},
 {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--export-denials-only=false"},
 {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"eventlog","mountPath":"/var/log/pahlevan"}},
 {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"eventlog","hostPath":{"path":"/var/log/pahlevan","type":"DirectoryOrCreate"}}}
]
JSON
sudo kubectl -n pahlevan-system patch ds pahlevan-agent --type=json --patch-file /tmp/export-patch.json
sudo kubectl -n pahlevan-system rollout status ds/pahlevan-agent --timeout=240s
sudo kubectl -n pahlevan-system get pods -o wide
EOF
}

pahlevan_policy() {
  log "PAHLEVAN: apply the policy (learn 180s -> Blocking) and restart the target under the agent"
  vms pahlevan-policy <<'EOF'
set -eu
cat > /tmp/policy.yaml <<'YAML'
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata: {name: protect-target, namespace: bench}
spec:
  selector: {matchLabels: {app: target}}
  learningConfig: {duration: 180s, autoTransition: true}
  enforcementConfig: {mode: Blocking, alertOnly: false, blockUnknown: true}
  filePolicy: {defaultAction: Deny}
YAML
sudo kubectl apply -f /tmp/policy.yaml
# The workload has to (re)start under a running agent or its baseline is missed.
sudo kubectl -n bench delete pod -l app=target --grace-period=5 --wait=true
sudo kubectl -n bench rollout status deploy/target --timeout=180s
sleep 5
EOF
}

pahlevan_learn() {
  log "PAHLEVAN: drive benign traffic through the learning window"
  vms pahlevan-learn <<'EOF'
set -eu
PODIP=$(sudo kubectl -n bench get pod -l app=target -o jsonpath='{.items[0].status.podIP}')
end=$((SECONDS+150))
while [ $SECONDS -lt $end ]; do curl -s -o /dev/null "http://$PODIP/" || true; sleep 0.3; done
echo "benign traffic done"
EOF
}

# pahlevan_wait_enforce - poll the four per-cgroup mode maps until the target
# cgroup is enforcing, then hold until the self-healing observation window has
# passed.
#
# Why the hold: internal/adaptive DefaultRollbackConfig watches each container for
# ObservationWindow=5m after the enforce transition and rolls enforcement back to
# learning as soon as DenialThreshold=10 in-kernel denials land in that window.
# The attack suite trips that in seconds, so a run started immediately after the
# transition measures ten denials and then an unenforced cluster. Those settings
# are compiled into the agent (no CRD field, no flag reaches them), so the only
# way to measure a steady enforcing state at stock configuration is to wait the
# observation window out. Past it, rollback is no longer evaluated.
#
# The rollback behaviour itself is measured separately and reported; this step
# just establishes the steady state the matrix is taken in.
PAHLEVAN_SETTLE="${PAHLEVAN_SETTLE:-330}"
pahlevan_wait_enforce() {
  log "PAHLEVAN: wait for learn -> enforce, then hold past the rollback observation window"
  "${VM_CP}" "${BENCH_DIR}/modes.py" /tmp/modes.py >/dev/null
  vms pahlevan-enforce <<EOF
set -eu
. /tmp/bench-facts
SETTLE=${PAHLEVAN_SETTLE}
ENFORCE_AT=""
for i in \$(seq 1 180); do
  OUT=\$(sudo python3 /tmp/modes.py "\$CGIDS" 2>/dev/null || true)
  E=\$(printf '%s' "\$OUT" | sed -n 's/^ENFORCING //p')
  if [ -n "\$E" ]; then
    ENFORCE_AT=\$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "ENFORCE_AT=\$ENFORCE_AT"
    echo "ENFORCE_MECHANISMS=\$E"
    break
  fi
  sleep 10
done
if [ -z "\$ENFORCE_AT" ]; then
  echo "ENFORCEMENT_NEVER_STARTED=1"
  sudo python3 /tmp/modes.py "\$CGIDS" || true
  exit 0
fi
echo "holding \${SETTLE}s so the self-healing observation window (5m) elapses..."
ROLLBACKS=0
end=\$((SECONDS+SETTLE))
while [ \$SECONDS -lt \$end ]; do
  sleep 15
  OUT=\$(sudo python3 /tmp/modes.py "\$CGIDS" 2>/dev/null || true)
  E=\$(printf '%s' "\$OUT" | sed -n 's/^ENFORCING //p')
  if [ -z "\$E" ]; then
    ROLLBACKS=\$((ROLLBACKS+1))
    echo "ROLLBACK_OBSERVED at \$(date -u +%H:%M:%SZ) (count=\$ROLLBACKS); waiting for the next transition"
    # Restart the settle clock once enforcement comes back.
    for j in \$(seq 1 180); do
      OUT=\$(sudo python3 /tmp/modes.py "\$CGIDS" 2>/dev/null || true)
      E=\$(printf '%s' "\$OUT" | sed -n 's/^ENFORCING //p')
      [ -n "\$E" ] && break
      sleep 10
    done
    [ -z "\$E" ] && { echo "ENFORCEMENT_DID_NOT_RETURN=1"; break; }
    echo "ENFORCE_AT=\$(date -u +%Y-%m-%dT%H:%M:%SZ) (after rollback)"
    end=\$((SECONDS+SETTLE))
  fi
done
echo "ROLLBACKS_DURING_SETTLE=\$ROLLBACKS"
echo "--- final mode maps ---"
sudo python3 /tmp/modes.py "\$CGIDS" || true
echo "--- allow-set sizes ---"
for m in file_allowed exec_allowed network_allowed cap_allowed; do
  echo "\$m: \$(sudo bpftool -j map dump name \$m 2>/dev/null | grep -o '"key"' | wc -l)"
done
echo "--- agent restarts ---"
sudo kubectl -n pahlevan-system get pod -l app.kubernetes.io/name=pahlevan-agent \
  -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}'; echo
echo "--- workload still serving? ---"
PODIP=\$(sudo kubectl -n bench get pod -l app=target -o jsonpath='{.items[0].status.podIP}')
curl -s -o /dev/null -w 'nginx_http_code=%{http_code}\n' --max-time 5 "http://\$PODIP/" || echo 'nginx_http_code=ERR'
echo "--- policy status ---"
sudo kubectl -n bench get pahlevanpolicy protect-target -o yaml | sed -n '/^status:/,\$p' | head -40
EOF
}

# pahlevan_exec_probe - does `kubectl exec` still work while enforcing? The
# 2026-08-14 run found it does not; record the current behaviour either way.
pahlevan_exec_probe() {
  log "PAHLEVAN: probe whether kubectl exec is refused while enforcing"
  vms pahlevan-exec-probe <<'EOF'
set -eu
. /tmp/bench-facts
set +e
OUT=$(sudo kubectl -n bench exec "$POD" -- /bin/true 2>&1); RC=$?
set -e
echo "EXEC_PROBE_RC=$RC"
echo "EXEC_PROBE_OUT=$OUT"
EOF
}

run_pahlevan() {
  mkdir -p "${RESULTS}/pahlevan"
  build_pahlevan
  deploy_pahlevan
  pahlevan_policy
  stage_scenarios
  target_facts >"${RESULTS}/pahlevan/facts.txt"
  vm 'cat /tmp/bench-facts'
  start_runner
  pahlevan_learn
  pahlevan_wait_enforce   | tee "${RESULTS}/pahlevan/enforce.txt"
  pahlevan_exec_probe     | tee "${RESULTS}/pahlevan/execprobe.txt"
  arm_and_wait
  fetch_scenarios pahlevan

  log "PAHLEVAN: collect signals (JSON-lines event export) and agent logs"
  vm 'sudo cat /var/log/pahlevan/events.jsonl 2>/dev/null || true' >"${RESULTS}/pahlevan/signals.raw" || true
  wc -l "${RESULTS}/pahlevan/signals.raw" || true
  vm 'sudo kubectl -n pahlevan-system logs ds/pahlevan-agent --tail=200000 2>&1 | grep -v "DEBUG.*observer" | tail -200 || true' \
    >"${RESULTS}/pahlevan/agent.log" 2>&1 || true
  vm 'sudo kubectl -n pahlevan-system get pods -o wide; sudo kubectl -n pahlevan-system describe pod -l app.kubernetes.io/name=pahlevan-agent | sed -n "/Last State/,/Ready/p"' \
    >>"${RESULTS}/pahlevan/meta.txt" 2>&1 || true
  # Enforcement state AFTER the suite: did self-healing roll it back mid-run?
  vm 'sudo python3 /tmp/modes.py "$(sed -n "s/^CGIDS=//p" /tmp/bench-facts)"' \
    >"${RESULTS}/pahlevan/enforce-after.txt" 2>&1 || true
  cat "${RESULTS}/pahlevan/enforce-after.txt" || true

  log "PAHLEVAN: agent resources + BPF map memlock"
  measure_agent 'app.kubernetes.io/name=pahlevan-agent' pahlevan-system 'pahlevan-agent' \
    >"${RESULTS}/pahlevan/resources.txt" 2>&1 || true
  measure_bpf_maps >>"${RESULTS}/pahlevan/resources.txt" 2>&1 || true
  cat "${RESULTS}/pahlevan/resources.txt" || true

  log "PAHLEVAN: teardown"
  vms pahlevan-teardown <<'EOF'
set -eu
sudo kubectl -n bench delete pahlevanpolicy protect-target --ignore-not-found --grace-period=5 || true
sudo kubectl delete -f /tmp/install-bench.yaml --grace-period=5 --ignore-not-found || true
sudo kubectl delete crd pahlevanpolicies.policy.pahlevan.io --ignore-not-found || true
sudo kubectl delete clusterrole pahlevan-agent pahlevan-operator pahlevan-agent-bench-extra --ignore-not-found || true
sudo kubectl delete clusterrolebinding pahlevan-agent pahlevan-operator pahlevan-agent-bench-extra --ignore-not-found || true
sudo kubectl delete ns pahlevan-system --grace-period=5 --ignore-not-found || true
sleep 10
EOF
  correlate pahlevan
}

# --------------------------------------------------------------------------
# 5. Correlate one tool's raw stream into a per-scenario matrix
# --------------------------------------------------------------------------
correlate() {
  local tool="$1" dir="${RESULTS}/$1"
  log "${tool^^}: correlate signals to scenarios"
  local pod cgids
  pod="$(sed -n 's/^POD=//p' "${dir}/facts.txt" | head -1)"
  cgids="$(sed -n 's/^CGIDS=//p' "${dir}/facts.txt" | head -1)"
  python3 "${BENCH_DIR}/correlate.py" \
    --tool "${tool}" \
    --scenarios "${dir}/scenarios.txt" \
    --signals "${dir}/signals.raw" \
    --pod "${pod}" \
    --cgroups "${cgids}" \
    --out "${dir}/matrix.json" | tee "${dir}/matrix.txt"
}

# --------------------------------------------------------------------------
environment() {
  log "Environment"
  vms environment <<'EOF'
set -eu
echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "kernel: $(uname -r)"
echo "os: $(. /etc/os-release; echo "$PRETTY_NAME")"
echo "lsm: $(cat /sys/kernel/security/lsm)"
echo "cpus: $(nproc)  mem: $(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
echo "k3s: $(k3s --version | head -1)"
echo "containerd: $(sudo k3s ctr version | awk '/Version/{print $2; exit}')"
echo "helm: $(helm version --short)"
echo "kubectl: $(sudo kubectl version -o json 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["serverVersion"]["gitVersion"])' 2>/dev/null || echo '?')"
echo "cgroup: $(stat -fc %T /sys/fs/cgroup)"
EOF
}

main() {
  case "${1:-all}" in
  setup)    setup_cluster; deploy_target; environment | tee "${RESULTS}/environment.txt" ;;
  env)      environment | tee "${RESULTS}/environment.txt" ;;
  control)  run_control ;;
  pahlevan) run_pahlevan ;;
  all)      setup_cluster; deploy_target; environment | tee "${RESULTS}/environment.txt"
            run_control; run_pahlevan ;;
  *) echo "usage: $0 {setup|env|control|pahlevan|all}" >&2; exit 2 ;;
  esac
  log "Done. Artifacts in ${RESULTS}"
}
main "$@"
