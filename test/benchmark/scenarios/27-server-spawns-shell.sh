#!/usr/bin/env sh
# Tactic: Persistence (TA0003)
# Technique: Server Software Component - Web Shell (T1505.003); Command and
#            Scripting Interpreter - Unix Shell (T1059.004)
# Attack: a request-serving process runs a shell. This is what every web shell,
# every command injection and every exploited application server looks like
# from the kernel: php-fpm or apache2 execs sh, and the shell then does the
# attacker's work. The signal is the parent, not the child - the exec of sh is
# unremarkable on its own and is already in the baseline of any image whose
# entrypoint is a shell wrapper.
# Shape, not software: the pod under test is nginx, so this copies the shell to
# a path named php-fpm and runs the inner shell from it. What the kernel reports
# is a process whose comm is php-fpm execing sh, which is byte for byte the
# lineage a real FPM worker produces. Installing PHP to get the same two
# process records would not make the records any more real.
# Marker: outcome=allowed if the inner shell ran, blocked if it was prevented,
#         skipped if the copy could not be made.
set -u
TAG="27-server-spawns-shell"
KIND="attack"
DROP="/tmp/php-fpm"
rc=0
SH="$(command -v sh 2>/dev/null || echo /bin/sh)"
if cp "$SH" "$DROP" 2>/dev/null; then
  # The leading no-op makes the -c string a list rather than one simple
  # command. Some shells exec a lone simple command instead of forking, which
  # would collapse the two processes into one and destroy the very shape being
  # modelled. dash forks either way; this does not depend on which shell the
  # image ships.
  "$DROP" -c ': ; sh -c "id >/dev/null 2>&1"' >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
  rm -f "$DROP" 2>/dev/null || true
else
  rc=127
  OUT="skipped"
fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
