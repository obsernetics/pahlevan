#!/usr/bin/env bash
#
# pod-runner.sh - runs the scenario suite from INSIDE the target pod.
#
# Why a resident runner instead of one `kubectl exec` per scenario:
#
#   Pahlevan's enforcement is an in-kernel LSM decision on the target cgroup. Once
#   it is enforcing, the `runc exec` setup itself opens unlearned paths and every
#   `kubectl exec` into the pod is refused with EPERM. A harness that shells in per
#   scenario therefore measures exactly one thing ("exec is denied") and can tell
#   you nothing about which mechanism would have stopped which action. That is what
#   the 2026-08-14 run hit.
#
#   So this script is started while the tool under test is still learning/observing.
#   At that point it reads every scenario into memory, opens its output file and a
#   fifo, and then waits. From the trigger onward it uses ONLY bash builtins:
#   no `exec` of a new binary, no `open` of a new path. The harness therefore
#   cannot be blocked by the enforcement it is measuring, while everything the
#   scenarios do (exec cat/curl/timeout, open /etc/shadow, connect out) still goes
#   through the enforcement path exactly as an attacker's would.
#
#   Each scenario is run with `eval` inside a command substitution. A command
#   substitution is a fork, not an exec, so the scenario body runs under the
#   already-resident bash; the external binaries the scenario itself invokes are
#   the things being tested.
#
# The realistic-attacker assumption this bakes in: the attacker already has a
# shell in the compromised pod, so `bash` and its libraries are in the learned
# allow-list. That makes the tools' job HARDER, not easier, and is stated in the
# results.
#
# Lifecycle (all paths under /tmp/bench, staged from the node):
#   1. started during the learning/observe window   -> external commands allowed
#   2. loads scenarios, opens fd 9 (out.txt) and fd 8 (tick fifo), primes trigger
#   3. writes "RUNNER ready" and polls /tmp/bench/trigger for "go"
#   4. the node writes "go" into the trigger (through /proc/<pid>/root, so no
#      kubectl exec is needed and enforcement is not disturbed)
#   5. runs every scenario, appending one SCENARIO line per scenario to fd 9
#   6. writes "RUNNER done"
#
# usage: pod-runner.sh [gap-seconds]
#   gap-seconds: quiet time between scenarios so each tool's signals can be
#                attributed to one scenario by timestamp (default 3).

set -u

BENCH=/tmp/bench
GAP="${1:-3}"
TRIGGER_TIMEOUT="${2:-1200}"

mkdir -p "${BENCH}"
: >"${BENCH}/out.txt"
: >"${BENCH}/trigger"
[ -p "${BENCH}/tick" ] || mkfifo "${BENCH}/tick"

# fd 9: append-only results. Opened NOW, while opens are still allowed, and kept
# open, so writing results never triggers a file_open under enforcement.
exec 9>>"${BENCH}/out.txt"
# fd 8: a fifo opened read-write, so `read -t N -u 8` is a builtin sleep that
# neither reaches EOF nor needs /bin/sleep.
exec 8<>"${BENCH}/tick"

# Load every scenario body into memory (attacks first, then benign controls).
names=()
kinds=()
srcs=()
for f in "${BENCH}"/scenarios/*.sh; do
  [ -e "${f}" ] || continue
  names+=("${f##*/}")
  kinds+=("attack")
  srcs+=("$(<"${f}")")
done
for f in "${BENCH}"/scenarios/benign/*.sh; do
  [ -e "${f}" ] || continue
  names+=("${f##*/}")
  kinds+=("benign")
  srcs+=("$(<"${f}")")
done
# Mechanism probes: builtin-only actions that reach one specific kernel decision
# (socket_connect, file_open) without exec'ing a helper binary first. They are
# NOT part of the 26 attack scenarios and are never scored as such.
for f in "${BENCH}"/scenarios/probes/*.sh; do
  [ -e "${f}" ] || continue
  names+=("${f##*/}")
  kinds+=("probe")
  srcs+=("$(<"${f}")")
done

# Prime the trigger path into the allow-set while learning is still on.
_prime=$(<"${BENCH}/trigger")

printf 'RUNNER ready n=%s gap=%s ts=%s\n' "${#names[@]}" "${GAP}" "${EPOCHREALTIME}" >&9

# Wait for the node to arm the run. Pure builtins from here on.
deadline=$((EPOCHSECONDS + TRIGGER_TIMEOUT))
while :; do
  v=$(<"${BENCH}/trigger")
  case "${v}" in
  *go*) break ;;
  esac
  if ((EPOCHSECONDS > deadline)); then
    printf 'RUNNER trigger-timeout ts=%s\n' "${EPOCHREALTIME}" >&9
    exit 1
  fi
  read -r -t 1 -u 8 _ || true
done

printf 'RUNNER start ts=%s\n' "${EPOCHREALTIME}" >&9

i=0
n=${#names[@]}
while ((i < n)); do
  name="${names[i]}"
  kind="${kinds[i]}"
  src="${srcs[i]}"

  t0="${EPOCHREALTIME}"
  out=$(eval "${src}" 2>&1)
  rcx=$?
  t1="${EPOCHREALTIME}"

  # Extract the scenario's self-classifying marker with parameter expansion only.
  if [[ "${out}" == *BENCH_RESULT* ]]; then
    line="BENCH_RESULT${out#*BENCH_RESULT}"
    line="${line%%$'\n'*}"
  else
    # No marker: the scenario body itself could not get far enough to print one
    # (for example its interpreter was denied). Record that, do not guess.
    line="BENCH_RESULT tag=${name%.sh} kind=${kind} outcome=no-marker rc=${rcx}"
  fi

  printf 'SCENARIO name=%s kind=%s t0=%s t1=%s %s\n' \
    "${name}" "${kind}" "${t0}" "${t1}" "${line}" >&9

  read -r -t "${GAP}" -u 8 _ || true
  ((i++))
done

printf 'RUNNER done ts=%s\n' "${EPOCHREALTIME}" >&9
