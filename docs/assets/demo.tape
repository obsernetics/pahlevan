# demo.tape - charmbracelet/vhs script for Pahlevan's intro demo.
# Render with:  vhs docs/assets/demo.tape   (produces docs/assets/demo.gif)
#
# Nothing is typed into the terminal except commands. Narration would be a
# comment line the viewer has to read while the output they came for scrolls
# past, so the output does the explaining instead.
#
# It replays a real learn->enforce run: a static file server observed for 50
# minutes under continuous traffic on Linux 6.8.0 with the BPF LSM, then
# attacked. The numbers come from that run and from the VM suite; the helper
# shims live in docs/assets/demo.sh, which cites its sources line by line.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 820
Set Padding 24
Set Margin 12
Set BorderRadius 10
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms
Set PlaybackSpeed 1.0

Hide
Type "source docs/assets/demo.sh; clear" Enter
Show

# 1) a policy that names a workload and nothing else
Type "kubectl apply -f app-policy.yaml"
Enter
Sleep 700ms

# 2) the learning window
Type "pahlevan status --watch"
Enter
Sleep 1400ms

# 3) learned versus enforcing, on one screen
Type "compare_view"
Enter
Sleep 3600ms

# 4) the workload's own traffic keeps working
Type "allow_probe"
Enter
Sleep 1500ms

# 5) an attacker with a shell in the pod
Type 'kubectl exec -it app-7c9b4 -- python3 -c "open(/etc/shadow).read()"'
Enter
Sleep 1500ms

Type 'kubectl exec -it app-7c9b4 -- sh -c "echo backdoor >> /etc/passwd"'
Enter
Sleep 1600ms

Type "kubectl exec -it app-7c9b4 -- /tmp/xmrig"
Enter
Sleep 1500ms

# 6) a learned binary launched by the wrong parent
Type "kubectl exec -it app-7c9b4 -- sh -c /usr/bin/psql"
Enter
Sleep 1700ms

# 7) a syscall whose argument is the whole signal
Type 'kubectl exec -it app-7c9b4 -- python3 -c "ptrace(PTRACE_ATTACH, 1)"'
Enter
Sleep 1800ms

# 8) privilege gained where no execve explains it
Type 'kubectl exec -it app-7c9b4 -- ./escalate'
Enter
Sleep 1700ms

# 9) a shell builtin, which produces no exec, open or connect
Type "kubectl exec -it app-7c9b4 -- history -c"
Enter
Sleep 1700ms

# 10) every one of those is a real event
Type "pahlevan events --denials-only"
Enter
Sleep 3000ms

# 11) and reaches the people who act on it, formatted
Type "pahlevan notify --preview"
Enter
Sleep 2400ms

# 12) what the seven programs cover
Type "pahlevan coverage"
Enter
Sleep 2600ms

Type "pahlevan attack-surface report"
Enter
Sleep 2600ms
