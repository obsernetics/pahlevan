#!/usr/bin/env bash
#
# Re-render docs/assets/*.png from their sources in docs/assets/diagrams/.
#
# The diagrams are authored as self-contained HTML so they can be edited as
# design rather than redrawn as SVG path data by hand, and rendered here with
# headless Chrome at 2x so the text stays crisp on a high-density screen.
#
# Run this after editing a diagram source. An image that is regenerated from a
# committed source cannot drift from it the way a hand-exported one does; this
# is the same reason docs/assets/demo.tape sits next to demo.gif.
#
# Usage: hack/render-diagrams.sh [name ...]   (default: all of them)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

CHROME="${CHROME:-}"
if [ -z "$CHROME" ]; then
	for c in google-chrome-stable google-chrome chromium chromium-browser; do
		if command -v "$c" >/dev/null 2>&1; then CHROME="$c"; break; fi
	done
fi
if [ -z "$CHROME" ]; then
	echo "no Chrome or Chromium found; set CHROME=/path/to/chrome" >&2
	exit 1
fi

# Each entry is name:width:height, matching the root element in the source.
DIAGRAMS=(
	"learn-then-enforce:1240:512"
	"kernel-programs:1240:720"
)

want=("$@")
rendered=0

for entry in "${DIAGRAMS[@]}"; do
	IFS=: read -r name w h <<<"$entry"
	if [ ${#want[@]} -gt 0 ]; then
		match=0
		for x in "${want[@]}"; do [ "$x" = "$name" ] && match=1; done
		[ "$match" = 1 ] || continue
	fi

	src="docs/assets/diagrams/${name}.html"
	[ -f "$src" ] || { echo "missing $src" >&2; exit 1; }

	# The source is a design component: lift the markup and its styles out of
	# the wrapper into a plain page Chrome can shoot.
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	python3 - "$src" "$tmp/page.html" <<'PY'
import re, sys
src, out = sys.argv[1], sys.argv[2]
s = open(src).read()
body = s.split('<x-dc>', 1)[1].split('</x-dc>', 1)[0]
helmet = re.search(r'<helmet>(.*?)</helmet>', body, re.S)
head = helmet.group(1) if helmet else ''
content = re.sub(r'<helmet>.*?</helmet>', '', body, flags=re.S).strip()
open(out, 'w').write(
    '<!doctype html><html><head><meta charset="utf-8">' + head +
    '<style>html,body{margin:0;padding:0;background:#0b1020;}</style>'
    '</head><body>' + content + '</body></html>')
PY

	"$CHROME" --headless --no-sandbox --disable-gpu --hide-scrollbars \
		--force-device-scale-factor=2 --window-size="${w},${h}" \
		--virtual-time-budget=5000 \
		--screenshot="docs/assets/${name}.png" \
		"file://$tmp/page.html" >/dev/null 2>&1

	# -s is not enough: Chrome writes a screenshot of its own error page when it
	# cannot load the source, and that file is perfectly non-empty. The first
	# version of this script shipped exactly that. Check the image is the size
	# asked for and that its background is the dark canvas rather than the white
	# of an error page.
	python3 - "docs/assets/${name}.png" "$w" "$h" <<'PY'
import sys
from PIL import Image
path, w, h = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
im = Image.open(path).convert("RGB")
if im.size != (w * 2, h * 2):
    sys.exit(f"{path}: rendered {im.size[0]}x{im.size[1]}, expected {w*2}x{h*2}")
# The canvas is #0b1020. A Chrome error page is white; a blank render is white
# or transparent. Sample a few corners rather than one pixel.
for x, y in ((4, 4), (im.size[0] - 5, 4), (4, im.size[1] - 5)):
    r, g, b = im.getpixel((x, y))
    if r + g + b > 180:
        sys.exit(f"{path}: pixel at {x},{y} is {(r,g,b)}, too light for the "
                 f"diagram background - the source probably failed to load")
PY
	echo "rendered docs/assets/${name}.png ($(($(wc -c <"docs/assets/${name}.png") / 1024)) KB)"
	rendered=$((rendered + 1))
	rm -rf "$tmp"; trap - EXIT
done

[ "$rendered" -gt 0 ] || { echo "nothing matched" >&2; exit 1; }
