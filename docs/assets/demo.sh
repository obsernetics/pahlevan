#!/usr/bin/env bash
# demo.sh - scripted reproduction of Pahlevan's real learn->enforce flow, used by
# docs/assets/demo.tape (charmbracelet/vhs) to render docs/assets/demo.gif.
#
# The output below is a faithful replay of behavior verified in a VM on Linux 6.8
# with the BPF LSM enabled (lsm=bpf). It is a product demo, not a live cluster;
# the counts and messages mirror the real test output:
#   learned 28 (cgroup,path) allow-set entries
#   learned /etc/hostname allowed under enforcement
#   DENIED in-kernel as expected: cat /etc/os-release -> exit status 1
#
# It defines mock `kubectl` / `pahlevanctl` shims so the recorded terminal shows
# the same commands an operator would actually type.

B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; MAG=$'\033[35m'; GRY=$'\033[90m'

kubectl() {
  local sub="$1 $2"
  case "$sub" in
    "apply -f")
      echo "${GRN}pahlevanpolicy.policy.pahlevan.io/nginx-security created${R}"
      ;;
    "exec -it"|"exec -i")
      # everything after "--" is the attacker command
      shift
      while [ "$1" != "--" ] && [ $# -gt 0 ]; do shift; done
      shift
      echo "${GRY}# attacker shell inside the nginx pod${R}"
      echo "${DIM}\$ $*${R}"
      echo "cat: /etc/shadow: ${RED}Operation not permitted${R}"
      echo "${RED}command terminated with exit code 1${R}"
      echo "${MAG}[pahlevan/agent]${R} ${RED}DENIED${R} in-kernel (lsm/file_open, EPERM)  cgroup=nginx  path=/etc/shadow"
      ;;
    *) echo "$@" ;;
  esac
}

pahlevanctl() {
  local mode="status"; [ "$2" = "--watch" ] && mode="--watch"
  case "$mode" in
    --watch)
      local pct
      for pct in 0 15 32 48 63 79 90 100; do
        local filled=$(( pct / 5 )); local empty=$(( 20 - filled )); local bar=""
        local i; for ((i=0;i<filled;i++)); do bar+="#"; done
        for ((i=0;i<empty;i++)); do bar+="-"; done
        printf "\r  ${CYN}phase=Learning${R}  [%s] %3d%%  syscalls+file opens per cgroup" "$bar" "$pct"
        sleep 0.35
      done
      printf "\n"
      echo "  ${GRN}learned 28 (cgroup,path) allow-set entries${R}"
      echo "  ${B}phase=Learning -> phase=Enforcing${R}  (autoTransition)"
      ;;
    status)
      echo "${DIM}NAME             PHASE       ALLOW-SET   BLOCKED   MODE${R}"
      echo "nginx-security   ${GRN}Enforcing${R}   28          0         Blocking"
      ;;
  esac
}

# legit access performed by the real workload -> allowed under enforcement
allow_probe() {
  echo "${GRY}# workload reads a path it used during learning${R}"
  echo "${DIM}\$ cat /etc/hostname${R}"
  echo "nginx-7c9b4"
  echo "${GRN}[pahlevan/agent] ALLOW${R} /etc/hostname (in learned allow-set)"
}
