#!/usr/bin/env bash
# demo.sh - scripted reproduction of Pahlevan's real learn->enforce flow, used by
# docs/assets/demo.tape (charmbracelet/vhs) to render docs/assets/demo.gif.
#
# It is a product demo, not a live cluster. Every number and message below is
# taken from a real run, so the recording shows what the tool does rather than
# what someone wished it did. The sources:
#
#   hack/demo/scenario, run for 50 minutes on Linux 6.8.0 with the BPF LSM
#   active (lsm=bpf, confirmed in /sys/kernel/security/lsm). A static file
#   server ran under continuous traffic while the data plane learned, then
#   enforcement was switched on and the workload was attacked with nine
#   scenarios. See docs/live-scenario.md, and docs/scenario-report.md for the
#   full report the harness wrote.
#
#     learned 1 binary, 118 files, 6 destinations, 1 capability
#     1509 requests served, 0 failed
#     8 attacks refused, both controls still served
#
#   pkg/ebpf/vmload_test.go, the VM suite, for the individual hook behavior:
#
#     DENIED in-kernel: cat /etc/os-release -> exit status 1
#     DENIED in-kernel: exec /tmp/pahlevan-unlearned -> exit status 126
#     DENIED in-kernel: parent sh not in the process filter -> exit status 126
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
      echo "${GRY}# attacker shell inside the app pod${R}"
      case "$*" in
        *shadow*)
          echo "${DIM}\$ $*${R}"
          echo "PermissionError: [Errno 1] ${RED}Operation not permitted${R}: '/etc/shadow'"
          echo "$AGENT ${RED}DENIED${R} lsm/file_open      EPERM  read  path=/etc/shadow"
          ;;
        *passwd*)
          echo "${DIM}\$ $*${R}"
          echo "sh: 1: cannot create /etc/passwd: ${RED}Operation not permitted${R}"
          echo "$AGENT ${RED}DENIED${R} lsm/file_open      EPERM  ${B}write${R} path=/etc/passwd"
          echo "  ${GRY}the startup read of /etc/passwd was learned; the write is a separate entry${R}"
          ;;
        *socket*|*connect*)
          echo "${DIM}\$ $*${R}"
          echo "ConnectionRefusedError: [Errno 1] ${RED}Operation not permitted${R}"
          echo "$AGENT ${RED}DENIED${R} lsm/socket_connect EPERM  dst=203.0.113.7:4444 ${YEL}[external]${R}"
          ;;
        *mount*)
          echo "${DIM}\$ $*${R}"
          echo "mount rc -1 errno 1  (${RED}EPERM${R})"
          echo "$AGENT ${RED}DENIED${R} lsm/capable        EPERM  cap=CAP_SYS_ADMIN"
          ;;
        *xmrig*)
          echo "${DIM}\$ $*${R}"
          echo "sh: 1: /tmp/xmrig: ${RED}Operation not permitted${R}"
          echo "$AGENT ${RED}DENIED${R} lsm/bprm_check     EPERM  exec=/tmp/xmrig"
          echo "  ${GRY}the allow-set keys on the resolved path; no name makes it permitted${R}"
          ;;
        *psql*)
          echo "${DIM}\$ $*${R}"
          echo "sh: 1: /usr/bin/psql: ${RED}Operation not permitted${R}"
          echo "$AGENT ${RED}DENIED${R} lsm/bprm_check     EPERM  exec=/usr/bin/psql ${B}reason=process filter${R}"
          echo "  ${GRY}psql is learned. sh is not an allowed parent, so this exec is not${R}"
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
      echo "  ${GRN}learned 118 files, 1 exec, 6 destinations, 1 capability${R}  ${DIM}over 1509 requests${R}"
      echo "  ${B}phase=Learning -> phase=Enforcing${R}  (autoTransition, grace 30s elapsed)"
      ;;
    "status "*|"status")
      echo "${DIM}NAME             PHASE       FILES  EXEC  NET  CAPS  DENIED  MODE${R}"
      echo "nginx-security   ${GRN}Enforcing${R}   118    1     6    1     0       Blocking"
      ;;
    "events "*)
      echo "${DIM}TIME      KIND        DECISION  POD          DETAIL${R}"
      echo "12:04:11  file        ${RED}denied${R}    app-7c9b4    read /etc/shadow"
      echo "12:04:11  file        ${RED}denied${R}    app-7c9b4    write /etc/passwd"
      echo "12:04:11  network     ${RED}denied${R}    app-7c9b4    203.0.113.7:4444 ${YEL}external${R}"
      echo "12:04:12  capability  ${RED}denied${R}    app-7c9b4    CAP_SYS_ADMIN"
      echo "12:04:12  exec        ${RED}denied${R}    app-7c9b4    /tmp/xmrig"
      echo "12:04:13  exec        ${RED}denied${R}    app-7c9b4    /usr/bin/psql ${DIM}(process filter)${R}"
      echo ""
      echo "  ${GRY}same events reach Loki as OTLP log records, sharing the resource${R}"
      echo "  ${GRY}the metrics and traces carry, so Grafana joins them without a hand-written query${R}"
      ;;
    "attack-surface report"*)
      echo "${DIM}Workload            RISK  PORTS  WRITABLE  CAPS  SYSCALLS${R}"
      echo "app                 ${GRN}9${R}     1      2         1     41"
      echo ""
      echo "  ${B}seccomp profile${R}  allows ${GRN}53 of 373${R} syscalls  ${DIM}(41 learned + 12 baseline)${R}"
      ;;
    *) echo "$@" ;;
  esac
}

# legit access performed by the real workload -> allowed under enforcement
allow_probe() {
  echo "${GRY}# the workload keeps doing what it did during learning${R}"
  echo "${DIM}\$ curl -s -o /dev/null -w '%{http_code}' http://app.default.svc/health${R}"
  echo "200"
  echo "$AGENT ${GRN}ALLOW${R}  lsm/file_open      path=/srv/health"
  echo "$AGENT ${GRN}ALLOW${R}  lsm/socket_connect dst=${B}default/postgres${R}:5432  ${DIM}(10.104.22.9)${R}"
}
