# demo.tape - charmbracelet/vhs script for Pahlevan's intro demo.
# Render with:  vhs docs/assets/demo.tape   (produces docs/assets/demo.gif)
#
# It replays the REAL adaptive learn->enforce flow verified in a VM on Linux 6.8
# with the BPF LSM. The helper shims live in docs/assets/demo.sh.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 700
Set Padding 24
Set Margin 12
Set BorderRadius 10
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

# --- setup (hidden): load the scripted shims ---------------------------------
Hide
Type "source docs/assets/demo.sh; clear" Enter
Show

# --- title -------------------------------------------------------------------
Type "#  Pahlevan - eBPF Kubernetes runtime security: learn, then BLOCK in-kernel"
Sleep 1200ms
Enter
Sleep 600ms

# --- 1) apply an adaptive policy ---------------------------------------------
Type "kubectl apply -f nginx-policy.yaml"
Sleep 400ms
Enter
Sleep 1200ms

# --- 2) learning window (raw_tracepoint sys_enter + lsm/file_open) -----------
Type "pahlevanctl status --watch"
Sleep 400ms
Enter
Sleep 4200ms
Sleep 800ms

# --- 3) now enforcing --------------------------------------------------------
Type "pahlevanctl status"
Sleep 400ms
Enter
Sleep 1600ms

# --- 4) legit access stays allowed -------------------------------------------
Type "allow_probe"
Sleep 400ms
Enter
Sleep 1800ms

# --- 5) attacker reads a secret the workload never touched -> DENIED ----------
Type "#  attacker tries to exfiltrate credentials..."
Enter
Sleep 700ms
Type "kubectl exec -it nginx-7c9b4 -- cat /etc/shadow"
Sleep 400ms
Enter
Sleep 2600ms

Type "#  blocked in-kernel by LSM BPF - no rules written by hand."
Sleep 800ms
Enter
Sleep 2600ms
