package main

import (
	"encoding/xml"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/obsernetics/pahlevan/pkg/coverage"
)

// The landing page draws the architecture as an inline SVG. Two things went
// wrong with it at once, and nothing in the repo noticed either.
//
// It went stale: it showed three eBPF programs long after there were seven,
// so a reader evaluating the project saw a third of what it does.
//
// And it was clipped. A label anchored at its right-hand end sat at x=150 and
// was about 154px wide, so it began at roughly x=-4 and the page rendered
// "earning / enforcement status". Nothing catches that, because the SVG is
// still valid XML and the page still loads.
//
// These check both: every detector Pahlevan ships has to appear, and no label
// may run outside the canvas it is drawn on.

const sitePage = "../../pages/index.html"

// inlineSVG pulls the architecture SVG out of the page.
func inlineSVG(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(sitePage)
	if err != nil {
		t.Fatalf("reading the landing page: %v", err)
	}
	s := string(b)
	i := strings.Index(s, `<svg viewBox="0 0 760`)
	if i < 0 {
		t.Fatal("no architecture SVG on the landing page; it was renamed or removed")
	}
	j := strings.Index(s[i:], "</svg>")
	if j < 0 {
		t.Fatal("the architecture SVG is not closed")
	}
	return s[i : i+j+len("</svg>")]
}

func TestTheArchitectureDiagramIsValidXML(t *testing.T) {
	// A malformed SVG renders as nothing at all, and the page still returns
	// 200, so this is not something a link checker would find.
	var node struct{}
	if err := xml.Unmarshal([]byte(inlineSVG(t)), &node); err != nil {
		t.Fatalf("the architecture SVG does not parse: %v", err)
	}
}

// The README carries a second architecture SVG, a separate file from the one
// inlined on the landing page. Only the landing page was guarded, so this one
// went on showing three programs and calling the syscall tracepoint a raw
// tracepoint - the same staleness, in the file nothing was checking.
func TestTheREADMEDiagramShowsEveryDetector(t *testing.T) {
	b, err := os.ReadFile("../../docs/assets/architecture.svg")
	if err != nil {
		t.Fatalf("reading the README architecture diagram: %v", err)
	}
	assertShowsEveryDetector(t, string(b), "docs/assets/architecture.svg")
}

func TestTheArchitectureDiagramShowsEveryDetector(t *testing.T) {
	svg := inlineSVG(t)
	assertShowsEveryDetector(t, svg, "pages/index.html")
}

func assertShowsEveryDetector(t *testing.T, svg, where string) {
	t.Helper()
	for _, e := range coverage.Table {
		// The diagrams shorten the hooks to fit the boxes, so match on the
		// distinctive part rather than the full attach point.
		short := e.Hook
		if i := strings.LastIndex(short, "/"); i >= 0 {
			short = short[i+1:]
		}
		// lsm/bprm_check_security is drawn as lsm/bprm_check.
		if short == "bprm_check_security" {
			short = "bprm_check"
		}
		if !strings.Contains(svg, short) {
			t.Errorf("%s does not mention %s (%s), so it shows fewer programs than Pahlevan has",
				where, e.Hook, e.Detector)
		}
	}
}

// textEl is one <text> in the diagram.
type textEl struct {
	x        float64
	anchor   string
	fontSize float64
	mono     bool
	body     string
	raw      string
}

var (
	textRe   = regexp.MustCompile(`(?s)<text\s([^>]*)>(.*?)</text>`)
	attrRe   = regexp.MustCompile(`([a-z-]+)="([^"]*)"`)
	entityRe = regexp.MustCompile(`&[#a-zA-Z0-9]+;`)
)

func diagramText(t *testing.T) []textEl {
	t.Helper()
	svg := inlineSVG(t)
	var out []textEl
	for _, m := range textRe.FindAllStringSubmatch(svg, -1) {
		el := textEl{fontSize: 12, anchor: "start", raw: m[0]}
		for _, a := range attrRe.FindAllStringSubmatch(m[1], -1) {
			switch a[1] {
			case "x":
				el.x, _ = strconv.ParseFloat(a[2], 64)
			case "text-anchor":
				el.anchor = a[2]
			case "font-size":
				el.fontSize, _ = strconv.ParseFloat(a[2], 64)
			case "font-family":
				el.mono = strings.Contains(a[2], "mono")
			}
		}
		// An entity such as &#183; is one glyph, not six characters.
		el.body = entityRe.ReplaceAllString(m[2], "x")
		el.body = strings.TrimSpace(stripTags(el.body))
		out = append(out, el)
	}
	if len(out) == 0 {
		t.Fatal("no <text> elements found; the extraction is wrong and this test proves nothing")
	}
	return out
}

func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestNoDiagramLabelRunsOffTheCanvas(t *testing.T) {
	// The viewBox is 760 wide. Width is estimated from the glyph count, which
	// is approximate - but the failure this exists for is a label starting at
	// a negative x, and an approximation is plenty to catch that. The factors
	// are deliberately conservative so a near-miss is reported rather than
	// squeaked through.
	const canvas = 760.0
	const proportional = 0.52 // Inter, average advance as a fraction of em
	const monospace = 0.60    // JetBrains Mono

	for _, el := range diagramText(t) {
		if el.body == "" {
			continue
		}
		factor := proportional
		if el.mono {
			factor = monospace
		}
		w := float64(len([]rune(el.body))) * el.fontSize * factor

		var left, right float64
		switch el.anchor {
		case "middle":
			left, right = el.x-w/2, el.x+w/2
		case "end":
			left, right = el.x-w, el.x
		default:
			left, right = el.x, el.x+w
		}

		if left < 0 {
			t.Errorf("label %q (anchor=%s x=%g) starts at about x=%.0f, off the left edge; "+
				"it renders clipped", el.body, el.anchor, el.x, left)
		}
		if right > canvas {
			t.Errorf("label %q (anchor=%s x=%g) ends at about x=%.0f, past the %g-wide canvas; "+
				"it renders clipped", el.body, el.anchor, el.x, right, canvas)
		}
	}
}

func TestTheDiagramArrowsTerminateOnBoxes(t *testing.T) {
	// The round trip between the operator and the agent is two arrows. The
	// previous version drew one of them starting 12px above the agent box, so
	// it began in empty space, and the two ran at the same x. Both ends of
	// both arrows must sit on a box edge, and they must not share a column, or
	// the picture reads as a single line doubled back.
	svg := inlineSVG(t)
	lineRe := regexp.MustCompile(`<line x1="([\d.]+)" y1="([\d.]+)" x2="([\d.]+)" y2="([\d.]+)"`)
	var verticals [][4]float64
	for _, m := range lineRe.FindAllStringSubmatch(svg, -1) {
		var v [4]float64
		for i := 0; i < 4; i++ {
			v[i], _ = strconv.ParseFloat(m[i+1], 64)
		}
		if v[0] == v[2] { // vertical
			verticals = append(verticals, v)
		}
	}
	if len(verticals) < 2 {
		t.Fatalf("expected at least two vertical connectors, found %d", len(verticals))
	}

	// The operator box bottom is y=150; the agent box top is y=242. An
	// endpoint must be within a few px of one of those, allowing for the
	// arrowhead's overhang.
	const operatorBottom, agentTop, tol = 150.0, 242.0, 8.0
	near := func(a, b float64) bool { return a-b < tol && b-a < tol }

	cols := map[float64]bool{}
	for _, v := range verticals {
		y1, y2 := v[1], v[3]
		onBox := (near(y1, operatorBottom) || near(y1, agentTop)) &&
			(near(y2, operatorBottom) || near(y2, agentTop))
		if !onBox {
			t.Errorf("a vertical connector runs y=%g to y=%g, which does not join the operator "+
				"(y=%g) to the agent (y=%g); one end is in empty space",
				y1, y2, operatorBottom, agentTop)
		}
		cols[v[0]] = true
	}
	if len(cols) < len(verticals) {
		t.Error("two connectors share the same x, so the round trip reads as one line doubled back")
	}
}
