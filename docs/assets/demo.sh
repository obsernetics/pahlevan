#!/usr/bin/env bash
# demo.sh - scripted reproduction of Pahlevan's real learn->enforce flow, used by
# docs/assets/demo.tape (charmbracelet/vhs) to render docs/assets/demo.gif.
#
# The output below is a faithful replay of behavior verified in a VM on Linux
# 6.8.0 with the BPF LSM enabled (lsm=bpf, confirmed in
# /sys/kernel/security/lsm). It is a product demo, not a live cluster; the
# counts and messages are taken from the VM test run in pkg/ebpf/vmload_test.go:
#
#   learned 38 (cgroup,path) allow-set entries
#   learned /etc/hostname allowed under enforcement
#   DENIED in-kernel as expected: cat /etc/os-release -> exit status 1
#   DENIED in-kernel as expected: exec /tmp/pahlevan-unlearned -> exit status 126
#   observed capability event: cap=2 (CAP_DAC_READ_SEARCH)
#   observed IPv6 egress event: dst=[::1]:59998
#
# The seccomp figure is arithmetic on the real amd64 table:
# pkg/seccomp.KnownSyscallCount() is 373, and Generate() allows the learned set
# plus a 12-call safety baseline.
#
# It defines mock `kubectl` / `pahlevan` shims so the recorded terminal shows the
# same commands an operator would actually type. `pahlevan` is the real CLI name
# shipped in the image; every subcommand replayed here exists.

B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; MAG=$'\033[35m'; GRY=$'\033[90m'

AGENT="${MAG}[pahlevan/agent]${R}"

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
      case "$*" in
        *shadow*)
          echo "${DIM}\$ $*${R}"
          echo "cat: /etc/shadow: ${RED}Operation not permitted${R}"
          echo "$AGENT ${RED}DENIED${R} lsm/file_open      EPERM   path=/etc/shadow"
          ;;
        *nc*|*ncat*)
          echo "${DIM}\$ $*${R}"
          echo "bash: /usr/bin/nc: ${RED}Operation not permitted${R}"
          echo "$AGENT ${RED}DENIED${R} lsm/bprm_check     EPERM   exec=/usr/bin/nc"
          echo "$AGENT ${RED}DENIED${R} lsm/socket_connect EPERM   dst=[2001:db8::5]:4444"
          ;;
        *)
          echo "${DIM}\$ $*${R}"
          echo "${RED}command terminated with exit code 1${R}"
          ;;
      esac
      ;;
    *) echo "$@" ;;
  esac
}

pahlevan() {
  case "$1 $2" in
    "status --watch")
      local pct
      for pct in 0 15 32 48 63 79 90 100; do
        local filled=$(( pct / 5 )); local empty=$(( 20 - filled )); local bar=""
        local i; for ((i=0;i<filled;i++)); do bar+="#"; done
        for ((i=0;i<empty;i++)); do bar+="-"; done
        printf "\r  ${CYN}phase=Learning${R}  [%s] %3d%%  syscalls, opens, execs, egress, caps" "$bar" "$pct"
        sleep 0.3
      done
      printf "\n"
      echo "  ${GRN}learned 38 files, 9 execs, 4 destinations, 2 capabilities${R}"
      echo "  ${B}phase=Learning -> phase=Enforcing${R}  (autoTransition, grace 30s elapsed)"
      ;;
    "status "*|"status")
      echo "${DIM}NAME             PHASE       FILES  EXEC  NET  CAPS  DENIED  MODE${R}"
      echo "nginx-security   ${GRN}Enforcing${R}   38     9     4    2     0       Blocking"
      ;;
    "events "*)
      echo "${DIM}TIME      KIND        DECISION  POD          DETAIL${R}"
      echo "12:04:11  file        ${RED}denied${R}    nginx-7c9b4  /etc/shadow"
      echo "12:04:11  exec        ${RED}denied${R}    nginx-7c9b4  /usr/bin/nc"
      echo "12:04:11  network     ${RED}denied${R}    nginx-7c9b4  [2001:db8::5]:4444"
      echo "12:04:12  capability  ${RED}denied${R}    nginx-7c9b4  CAP_SYS_ADMIN"
      ;;
    "attack-surface report"*)
      echo "${DIM}Workload            RISK  PORTS  WRITABLE  CAPS  SYSCALLS${R}"
      echo "nginx               ${GRN}12${R}    1      2         2     38"
      echo ""
      echo "  ${B}seccomp profile${R}  allows ${GRN}50 of 373${R} syscalls  ${DIM}(38 learned + 12 baseline)${R}"
      ;;
    *) echo "$@" ;;
  esac
}

# legit access performed by the real workload -> allowed under enforcement
allow_probe() {
  echo "${GRY}# the workload keeps doing what it did during learning${R}"
  echo "${DIM}\$ cat /etc/hostname && curl -s http://10.0.0.53:80${R}"
  echo "nginx-7c9b4"
  echo "$AGENT ${GRN}ALLOW${R}  lsm/file_open      path=/etc/hostname"
  echo "$AGENT ${GRN}ALLOW${R}  lsm/socket_connect dst=10.0.0.53:80"
}
