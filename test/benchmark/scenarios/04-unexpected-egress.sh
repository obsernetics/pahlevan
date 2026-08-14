#!/usr/bin/env sh
# Attack: connect out to a destination not seen during baseline (C2/exfil shape).
set -e
(wget -q -T 3 -O /dev/null http://198.51.100.10/ 2>&1 || true)
echo "EGRESS_ATTEMPTED rc=$?"
