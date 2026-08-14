#!/usr/bin/env bash
#
# run.sh - Reproducible Pahlevan vs Falco vs Tetragon runtime-security benchmark.
#
# Runs INSIDE the kernel-isolated VM (hack/vm/). eBPF is never loaded on the host.
# The VM here has only ~3.8 GiB RAM, so the three agents are run ONE AT A TIME
# against the SAME target workload and the SAME scenarios, then torn down. All
# numbers this produces are real measurements; see docs/benchmarks/results.md for
# a recorded run (2026-08-14) and the honest caveats.
#
# Usage (from the repo root, on the host):
#   hack/vm/up.sh                      # boot the VM (kernel 6.8, bpf LSM active)
#   test/benchmark/run.sh pahlevan     # build+deploy Pahlevan, learn, enforce, attack
#   test/benchmark/run.sh falco        # deploy Falco (modern eBPF), attack
#   test/benchmark/run.sh tetragon     # deploy Tetragon, attack (observe-only)
#   test/benchmark/run.sh all          # sequentially: setup + pahlevan + falco + tetragon
#
# Prereqs installed by this script inside the VM if missing: k3s, helm.
#
# Steps are intentionally explicit (not hidden behind helpers) so a reader can
# see exactly what was measured. Commands are run in the VM via hack/vm/run.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM_RUN="${REPO_ROOT}/hack/vm/run.sh"
VM_CP="${REPO_ROOT}/hack/vm/cp.sh"
SCRATCH="${SCRATCH:-/tmp/pahlevan-bench}"
mkdir -p "${SCRATCH}"

vm()  { "${VM_RUN}" "$*"; }
log() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

# --------------------------------------------------------------------------
# 0. Cluster + tooling (idempotent)
# --------------------------------------------------------------------------
setup_cluster() {
  log "Install k3s + helm in the VM (idempotent)"
  vm 'command -v k3s >/dev/null 2>&1 || curl -sfL https://get.k3s.io | sudo INSTALL_K3S_EXEC="--write-kubeconfig-mode=644 --disable=traefik --disable=metrics-server" sh -'
  vm 'command -v helm >/dev/null 2>&1 || (curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash)'
  vm 'sudo kubectl wait --for=condition=Ready node --all --timeout=120s'
  vm 'helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
      helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
      helm repo update >/dev/null 2>&1'
}

# --------------------------------------------------------------------------
# 1. Benign target workload (the thing all three tools "protect")
# --------------------------------------------------------------------------
deploy_target() {
  log "Deploy benign target workload (nginx:1.27, Debian -> has bash/curl for scenarios)"
  vm 'cat > /tmp/target.yaml <<EOF
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
EOF
  sudo kubectl apply -f /tmp/target.yaml
  sudo kubectl -n bench rollout status deploy/target --timeout=120s'
}

# Copy the scenario scripts (attacks + benign controls) into the VM. Idempotent.
stage_scenarios() {
  log "Stage scenario scripts into the VM (/tmp/bench-scenarios)"
  vm 'rm -rf /tmp/bench-scenarios'
  "${VM_CP}" -r "${REPO_ROOT}/test/benchmark/scenarios" /tmp/bench-scenarios
}

# Run every ATTACK scenario in the target pod, one per kubectl exec, piping each
# script to `sh` inside the pod. Each script prints a single self-classifying
# marker line:
#   BENCH_RESULT tag=<name> kind=attack outcome=<allowed|blocked|attempted|...> rc=<n>
# outcome=blocked  -> the in-pod action was PREVENTED (blocked=Yes for this tool)
# outcome=allowed  -> the action completed          (blocked=No)
# outcome=attempted-> success is ambiguous from inside the pod (network reaching
#                     an unroutable dest, path-absent probes); judge blocking
#                     from the tool's own logs, not from rc.
# If the pod's `exec` itself is denied (e.g. Pahlevan enforcing on the runc exec
# setup), no marker is printed and the outcome is recorded as exec-blocked.
# "Detected" is NOT decided here: it is read from each tool's signal source
# (Pahlevan kernel maps / logs, Falco alerts, Tetragon telemetry) below.
# Arg1 = a tag for log correlation.
run_scenarios() {
  local tag="$1"
  stage_scenarios
  vm "POD=\$(sudo kubectl -n bench get pod -l app=target -o jsonpath='{.items[0].metadata.name}')
  echo '### [$tag] ATTACK scenarios in '\$POD
  for f in /tmp/bench-scenarios/*.sh; do
    name=\$(basename \"\$f\")
    out=\$(sudo kubectl -n bench exec -i \$POD -- sh < \"\$f\" 2>&1); krc=\$?
    line=\$(printf '%s\n' \"\$out\" | grep '^BENCH_RESULT' | tail -1)
    if [ -z \"\$line\" ]; then
      if [ \$krc -ne 0 ]; then
        line=\"BENCH_RESULT tag=\$name kind=attack outcome=exec-blocked rc=\$krc\"
      else
        line=\"BENCH_RESULT tag=\$name kind=attack outcome=harness-error rc=\$krc\"
      fi
    fi
    printf '[%s] %s\n' '$tag' \"\$line\"
  done"
}

# Run every BENIGN control in the target pod. These are actions a normal nginx
# workload legitimately performs; the correct outcome is ALWAYS 'allowed'. Any
# other outcome (blocked/failed) is a FALSE POSITIVE counted against the tool.
# Benign controls are NEVER counted as attacks. Arg1 = a tag for log correlation.
run_benign() {
  local tag="$1"
  stage_scenarios
  vm "POD=\$(sudo kubectl -n bench get pod -l app=target -o jsonpath='{.items[0].metadata.name}')
  echo '### [$tag] BENIGN controls (false-positive check) in '\$POD
  for f in /tmp/bench-scenarios/benign/*.sh; do
    name=\$(basename \"\$f\")
    out=\$(sudo kubectl -n bench exec -i \$POD -- sh < \"\$f\" 2>&1); krc=\$?
    line=\$(printf '%s\n' \"\$out\" | grep '^BENCH_RESULT' | tail -1)
    if [ -z \"\$line\" ]; then
      if [ \$krc -ne 0 ]; then
        line=\"BENCH_RESULT tag=\$name kind=benign outcome=blocked rc=\$krc\"
      else
        line=\"BENCH_RESULT tag=\$name kind=benign outcome=harness-error rc=\$krc\"
      fi
    fi
    case \"\$line\" in
      *outcome=allowed*) printf '[%s] %s  (OK)\n' '$tag' \"\$line\" ;;
      *) printf '[%s] %s  (FALSE POSITIVE: benign action was blocked or failed)\n' '$tag' \"\$line\" ;;
    esac
  done"
}

# Sample agent pod CPU (15s) + memory from cgroup v2. Arg1 = label selector, arg2 = namespace.
measure_agent() {
  local sel="$1" ns="$2"
  vm "AUID=\$(sudo kubectl -n ${ns} get pod -l ${sel} -o jsonpath='{.items[0].metadata.uid}'); U=\${AUID//-/_}
  PS=\$(find /sys/fs/cgroup -type d -path \"*pod\${U}*.slice\" 2>/dev/null | grep -v cri-containerd | head -1)
  echo \"agent mem: \$(awk '{printf \"%.0f MiB\", \$1/1048576}' \$PS/memory.current)\"
  u1=\$(awk '/usage_usec/{print \$2}' \$PS/cpu.stat); t1=\$(date +%s%N); sleep 15
  u2=\$(awk '/usage_usec/{print \$2}' \$PS/cpu.stat); t2=\$(date +%s%N)
  awk -v a=\$u1 -v b=\$u2 -v c=\$t1 -v d=\$t2 'BEGIN{printf \"agent CPU (idle): %.2f%% of one core\n\",(b-a)*1000*100/(d-c)}'"
}

# --------------------------------------------------------------------------
# 2. PAHLEVAN
# --------------------------------------------------------------------------
#
# NOTE (2026-08-14): the committed agent on branch redesign/daemonset-agent-operator
# crash-loops as-is. Two one-line fixes are needed to get a running agent (do NOT
# commit these to the repo; apply them to a build copy):
#   (a) cmd/pahlevan-agent/main.go: remove the direct AttachPrograms() call
#       (Manager.Start() already attaches -> otherwise sys_enter EEXIST crashloop).
#   (b) internal/controller/attack_surface_controller.go: give the controller an
#       explicit .Named("attacksurfaceanalyzer") (it and PahlevanPolicyReconciler
#       both For(&PahlevanPolicy{}) -> duplicate controller name -> fatal).
# See docs/benchmarks/results.md "Pahlevan deployability".
run_pahlevan() {
  log "PAHLEVAN: build image (on host), import into k3s"
  # Build from a clean context (exclude .vmcache which holds the multi-GB VM disk).
  local SRC="${SCRATCH}/src"
  rm -rf "${SRC}"; mkdir -p "${SRC}"
  rsync -a --exclude='.vmcache' --exclude='.git' "${REPO_ROOT}/" "${SRC}/"
  # (Apply the two workaround patches to ${SRC} here if reproducing the 2026-08-14 run.)
  docker build -t pahlevan:bench --target runtime "${SRC}"
  docker save pahlevan:bench -o "${SCRATCH}/pahlevan-bench.tar"
  "${VM_CP}" "${SCRATCH}/pahlevan-bench.tar" /tmp/pahlevan-bench.tar
  vm 'sudo k3s ctr images import /tmp/pahlevan-bench.tar'

  log "PAHLEVAN: deploy (agent privileged for eBPF/LSM + bpffs bidirectional mount)"
  "${VM_CP}" "${REPO_ROOT}/install.yaml" /tmp/install.yaml
  vm 'sed -e "s#ghcr.io/obsernetics/pahlevan:latest#docker.io/library/pahlevan:bench#g" \
          -e "s#imagePullPolicy: IfNotPresent#imagePullPolicy: Never#g" /tmp/install.yaml > /tmp/install-bench.yaml
      sed -i "0,/replicas: 2/s//replicas: 1/" /tmp/install-bench.yaml
      sed -i "s/          privileged: false/          privileged: true/" /tmp/install-bench.yaml
      sudo kubectl apply -f /tmp/install-bench.yaml
      sudo kubectl -n pahlevan-system rollout status ds/pahlevan-agent --timeout=180s'

  log "PAHLEVAN: apply policy (learn 30s -> Blocking), drive benign traffic, transition to enforce"
  vm 'cat > /tmp/policy.yaml <<EOF
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata: {name: protect-target, namespace: bench}
spec:
  selector: {matchLabels: {app: target}}
  learningConfig: {duration: 30s, autoTransition: true}
  enforcementConfig: {mode: Blocking, alertOnly: false, blockUnknown: true}
  filePolicy: {defaultAction: Deny}
EOF
  sudo kubectl apply -f /tmp/policy.yaml
  # Recreate the target so nginx runs fully UNDER the agent (else its events are missed).
  sudo kubectl -n bench delete pod -l app=target --grace-period=5
  sudo kubectl -n bench rollout status deploy/target --timeout=90s
  PODIP=$(sudo kubectl -n bench get pod -l app=target -o jsonpath="{.items[0].status.podIP}")
  echo "driving benign traffic for 45s (learning window 30s)..."
  end=$((SECONDS+45)); while [ $SECONDS -lt $end ]; do curl -s -o /dev/null http://$PODIP/; sleep 0.4; done
  echo "file_mode map (cgroupid -> 1=enforce):"; sudo bpftool map dump name file_mode 2>&1 | head'

  log "PAHLEVAN: run attack scenarios (expect blocks at file_open / exec setup)"
  run_scenarios pahlevan
  log "PAHLEVAN: run benign controls (false-positive check; expect all allowed)"
  run_benign pahlevan
  log "PAHLEVAN: agent resources"; measure_agent 'app.kubernetes.io/name=pahlevan-agent' pahlevan-system

  log "PAHLEVAN: teardown"
  vm 'sudo kubectl delete -f /tmp/install-bench.yaml --grace-period=5 || true
      sudo kubectl delete crd pahlevanpolicies.policy.pahlevan.io || true
      sudo kubectl delete clusterrole pahlevan-agent pahlevan-operator || true
      sudo kubectl delete clusterrolebinding pahlevan-agent pahlevan-operator || true
      sudo kubectl delete ns pahlevan-system --grace-period=5 || true'
}

# --------------------------------------------------------------------------
# 3. FALCO (alert-only by design; modern eBPF / CO-RE driver)
# --------------------------------------------------------------------------
run_falco() {
  log "FALCO: install (modern_ebpf), run scenarios, scrape alerts"
  vm 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
      sudo kubectl create ns falco 2>/dev/null || true
      helm install falco falcosecurity/falco -n falco \
        --set driver.kind=modern_ebpf --set tty=true \
        --set collectors.kubernetes.enabled=false --set falcosidekick.enabled=false \
        --wait --timeout=6m
      sudo kubectl -n falco rollout status ds/falco --timeout=180s'
  run_scenarios falco
  run_benign falco
  log "FALCO: alerts in the last 90s (Falco NEVER blocks; Blocked=No for all)"
  vm "sudo kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco --since=90s 2>&1 | grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.' | grep -iE 'Warning|Notice|Critical' | tail -20"
  log "FALCO: agent resources"; measure_agent 'app.kubernetes.io/name=falco' falco
  log "FALCO: teardown"
  vm 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; helm uninstall falco -n falco || true; sudo kubectl delete ns falco --grace-period=5 || true'
}

# --------------------------------------------------------------------------
# 4. TETRAGON (observe-only by default; enforcement needs a TracingPolicy)
# --------------------------------------------------------------------------
run_tetragon() {
  log "TETRAGON: install (defaults = process telemetry, no blocking)"
  vm 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
      helm install tetragon cilium/tetragon -n kube-system --wait --timeout=6m
      sudo kubectl -n kube-system rollout status ds/tetragon --timeout=180s'
  run_scenarios tetragon
  run_benign tetragon
  log "TETRAGON: process_exec events for the target pod (raw telemetry; Blocked=No by default)"
  vm "sudo kubectl -n kube-system logs -l app.kubernetes.io/name=tetragon -c export-stdout --since=90s 2>&1 | grep target-555 | grep -oE '\"binary\":\"[^\"]+\", \"arguments\":\"[^\"]+\"' | sort -u | head -20"
  log "TETRAGON: agent resources"; measure_agent 'app.kubernetes.io/name=tetragon' kube-system

  # OPTIONAL enforcement demo. DANGER: an UN-SCOPED Sigkill TracingPolicy on
  # security_file_permission killed unrelated processes node-wide and froze the
  # VM on 2026-08-14, requiring an out-of-band reset. Left disabled by default.
  # To reproduce, ALWAYS add a pod/namespace selector to matchBinaries and test
  # in a disposable VM. See docs/benchmarks/results.md.
  #
  # vm 'sudo kubectl apply -f test/benchmark/tetragon-block-shadow.yaml'  # (author a scoped policy)

  log "TETRAGON: teardown"
  vm 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; helm uninstall tetragon -n kube-system || true'
}

# --------------------------------------------------------------------------
main() {
  case "${1:-all}" in
    setup)    setup_cluster; deploy_target ;;
    pahlevan) run_pahlevan ;;
    falco)    run_falco ;;
    tetragon) run_tetragon ;;
    all)      setup_cluster; deploy_target; run_pahlevan; run_falco; run_tetragon ;;
    *) echo "usage: $0 {setup|pahlevan|falco|tetragon|all}" >&2; exit 2 ;;
  esac
  log "Done. Record the matrix in docs/benchmarks/results.md"
}
main "$@"
