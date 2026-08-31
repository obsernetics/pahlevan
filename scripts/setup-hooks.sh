#!/usr/bin/env bash
#
# Point this clone at the repository's hooks. Run once after cloning.
#
# Git does not share hooks through the repository itself - .git/hooks is local
# and never committed - so a hook everyone is supposed to have needs one
# deliberate command per clone. core.hooksPath is that command.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "core.hooksPath set to .githooks"
echo "Installed:"
for h in .githooks/*; do
	[ -x "$h" ] && echo "  $(basename "$h")"
done
