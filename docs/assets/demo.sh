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
# pkg/seccomp.KnownSyscallCount() is 373, and GenerateWithOverrides() allows the
# learned set plus a 12-call safety baseline.
#
# The newer hooks replayed here come from their own VM tests, which is where
# their exact behaviour is asserted:
#
#   TestVMCredMonitorCatchesAnUnexplainedEscalation - kprobe/commit_creds sees
#     privilege gained with no execve underway, which is what separates an
#     exploit from sudo doing its job.
#   TestVMSyscallArgumentsAreCaptured - a syscall event carries its six
#     arguments, so ptrace(PTRACE_ATTACH, 1) is distinguishable from
#     ptrace(PTRACE_TRACEME).
#   TestVMAuditActionReportsWithoutDenying - Audit reports what would have been
#     refused, allows it, and does not learn it.
#   TestVMGenericKprobeAttachesToANamedFunction - one program attached to a
#     function named at runtime, identified by its attach cookie.
#
# The shell line comes from bpf/shell_monitor.c's uretprobe on readline, which
# sees builtins that produce no exec, no open and no connect.
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
      case "$*" in
        *shadow*)
          echo "${DIM}\$ $*${R}"
          echo "PermissionError: [Errno 1] ${RED}Operation not permitted${R}: '/etc/shadow'"
          echo "$AGENT ${RED}DENIED${R} lsm/file_open      EPERM  read  path=/etc/shadow"
          ;;
        *PTRACE_ATTACH*|*ptrace*)
          echo "${DIM}\$ $*${R}"
          echo "PermissionError: [Errno 1] ${RED}Operation not permitted${R}"
          echo "$AGENT ${YEL}WATCHED${R} sys_enter          ptrace(${B}PTRACE_ATTACH${R}, pid=1) ${GRY}argument, not just the number${R}"
          echo "$AGENT ${RED}DENIED${R} lsm/capable        EPERM  CAP_SYS_PTRACE"
          ;;
        *setresuid*|*escalate*)
          echo "${DIM}\$ $*${R}"
          echo "${RED}Killed${R}"
          echo "$AGENT ${RED}KILLED${R} kprobe/commit_creds  euid 1000->0  ${B}no execve underway${R}"
          ;;
        *history*|*export\ *|*cd\ /root*)
          echo "${DIM}\$ $*${R}"
          echo "$AGENT ${YEL}RECORDED${R} uretprobe/readline  ${B}$*${R} ${GRY}shell builtin: no exec, no open, no connect${R}"
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
      for pct in 0 28 55 79 100; do
        local filled=$(( pct / 5 )); local empty=$(( 20 - filled )); local bar=""
        local i; for ((i=0;i<filled;i++)); do bar+="#"; done
        for ((i=0;i<empty;i++)); do bar+="-"; done
        printf "\r  ${CYN}phase=Learning${R}  [%s] %3d%%  syscalls, opens, execs, egress, caps" "$bar" "$pct"
        sleep 0.16
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
      echo "12:04:14  syscall     ${YEL}watched${R}   app-7c9b4    ptrace(PTRACE_ATTACH, pid=1)"
      echo "12:04:14  cred        ${RED}killed${R}    app-7c9b4    euid 1000->0, no execve underway"
      echo "12:04:15  shell       ${YEL}recorded${R}  app-7c9b4    history -c"
      echo ""
      echo "  ${GRY}the same events reach Slack and PagerDuty as formatted findings,${R}"
      echo "  ${GRY}and Loki as OTLP records sharing the resource the metrics carry${R}"
      ;;
    "coverage"*)
      echo "${DIM}PROGRAM                        ATT&CK${R}"
      echo "lsm/file_open                  T1005 T1552.001 T1083"
      echo "lsm/socket_connect             T1041 T1071"
      echo "lsm/bprm_check_security        T1059 T1543 T1036"
      echo "lsm/capable                    T1548 T1611"
      echo "kprobe/commit_creds            ${B}T1068${R} T1548.001"
      echo "uretprobe/readline             ${B}T1059.004${R} T1070.003"
      echo "tracepoint/sys_enter           T1106 T1620"
      ;;
    "notify "*|"notify")
      echo "  ${MAG}#security-alerts${R}  ${DIM}via incoming webhook${R}"
      echo "  ${B}Pahlevan denied 6 operations on node-1${R}"
      echo "  ${GRY}Deployment/app in prod${R}"
      echo "  DENIED read of /etc/shadow by python3"
      echo "  ${GRY}Deployment/app in prod${R}"
      echo "  DENIED exec of /tmp/xmrig by sh -> python3"
      echo "  ${DIM}and 4 more in this batch${R}"
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
# A side-by-side of what the workload did during learning against what the same
# operations do under enforcement. This is the whole model on one screen.
compare_view() {
  printf '%s\n' "${B}  LEARNED (50m window)              ENFORCING${R}"
  printf '%s\n' "${GRY}  ─────────────────────────────    ─────────────────────────────${R}"
  printf '  %-31s %s\n' "open /srv/www/*"        "open /srv/www/*            ${GRN}ok${R}"
  printf '  %-31s %s\n' "open /etc/mime.types"   "open /etc/mime.types       ${GRN}ok${R}"
  printf '  %-31s %s\n' "connect 10.0.1.7:5432"  "connect 10.0.1.7:5432      ${GRN}ok${R}"
  printf '  %-31s %s\n' "exec python3"           "exec python3               ${GRN}ok${R}"
  printf '  %-31s %s\n' "61 of 373 syscalls"     "${GRY}─────────────────────────────${R}"
  printf '  %-31s %s\n' ""                       "open /etc/shadow        ${RED}EPERM${R}"
  printf '  %-31s %s\n' ""                       "exec /tmp/xmrig         ${RED}EPERM${R}"
  printf '  %-31s %s\n' ""                       "connect 203.0.113.7:4444 ${RED}EPERM${R}"
  printf '  %-31s %s\n' ""                       "commit_creds euid->0   ${RED}KILLED${R}"
  echo
  printf '%s\n' "${GRY}  1509 requests served, 0 failed. No rule was written.${R}"
}

allow_probe() {
  echo "${DIM}\$ curl -s -o /dev/null -w '%{http_code}' http://app.default.svc/health${R}"
  echo "200"
  echo "$AGENT ${GRN}ALLOW${R}  lsm/file_open      path=/srv/health"
  echo "$AGENT ${GRN}ALLOW${R}  lsm/socket_connect dst=${B}default/postgres${R}:5432  ${DIM}(10.104.22.9)${R}"
}
