# demo.tape - charmbracelet/vhs script for Pahlevan's intro demo.
# Render with:  vhs docs/assets/demo.tape   (produces docs/assets/demo.gif)
#
# It replays the REAL adaptive learn->enforce flow verified in a VM on Linux
# 6.8.0 with the BPF LSM (see pkg/ebpf/vmload_test.go). The helper shims live in
# docs/assets/demo.sh.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 760
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
Type "#  Pahlevan - it learns what your workload does, then blocks the rest in-kernel"
Sleep 1100ms
Enter
Sleep 500ms

# --- 1) apply an adaptive policy: no rules to write --------------------------
Type "kubectl apply -f nginx-policy.yaml"
Sleep 350ms
Enter
Sleep 1100ms

# --- 2) learning window: files, execs, egress, capabilities ------------------
Type "pahlevan status --watch"
Sleep 350ms
Enter
Sleep 3600ms
Sleep 700ms

# --- 3) now enforcing --------------------------------------------------------
Type "pahlevan status"
Sleep 350ms
Enter
Sleep 1500ms

# --- 4) the workload's normal behaviour keeps working ------------------------
Type "allow_probe"
Sleep 350ms
Enter
Sleep 1900ms

# --- 5) attacker reads a secret the workload never touched -> DENIED ---------
Type "#  attacker lands in the pod and goes for the credentials..."
Enter
Sleep 600ms
Type "kubectl exec -it nginx-7c9b4 -- cat /etc/shadow"
Sleep 350ms
Enter
Sleep 2200ms

# --- 6) and tries to exfiltrate: exec + egress, both denied ------------------
Type "kubectl exec -it nginx-7c9b4 -- nc [2001:db8::5] 4444"
Sleep 350ms
Enter
Sleep 2400ms

# --- 7) every denial is a real event you can ship somewhere ------------------
Type "pahlevan events --denials-only"
Sleep 350ms
Enter
Sleep 2400ms

# --- 8) the payoff -----------------------------------------------------------
Type "pahlevan attack-surface report"
Sleep 350ms
Enter
Sleep 2600ms

Type "#  No hand-written rules. Denied in-kernel by LSM BPF, before the syscall returns."
Sleep 800ms
Enter
Sleep 2800ms
