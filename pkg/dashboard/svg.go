package dashboard

import (
	"html"
	"net/http"
	"strconv"
	"strings"
)

// Diagrams, drawn here rather than in the browser.
//
// The obvious way to draw a flow or a tree in a web page is to pull a charting
// library from a CDN, and that is exactly what the Content-Security-Policy in
// security.go forbids: a dashboard that loads code from a third party at
// runtime has made every viewer's browser trust that third party, and a
// security tool does not get to make that trade on a user's behalf. Vendoring
// a library instead would only move the problem to "a megabyte of someone
// else's JavaScript, forever, for four diagrams".
//
// So the server emits SVG. It is text, it is deterministic, it is testable
// without a browser, and the only thing the page has to do with it is put it
// in the document. Colour and typography come from app.css through class
// attributes; nothing here emits a style attribute, because style-src in the
// policy has no 'unsafe-inline' and an inline style would silently not apply.

// Diagram geometry. The numbers are chosen so a diagram is legible at the
// width a sidebar leaves and still readable on a phone, where the page scales
// the viewBox down rather than reflowing.
const (
	flowBoxWidth  = 200
	flowBoxHeight = 96
	flowGap       = 48
	flowMargin    = 16

	barRowHeight = 34
	barLabelCols = 120
	barTrackCols = 320

	treeRowHeight = 26
	treeIndent    = 26
	treeMaxRows   = 120
)

// FlowSVG draws the learning-to-enforcement flow as connected stages.
//
// A phase string answers the wrong question: "Enforcing" does not say that it
// got there on the third attempt after two rollbacks, and that is the single
// most useful thing to know about a profile somebody is deciding whether to
// trust. The flow shows every stage, which one is live, and which one failed.
func FlowSVG(stages []FlowStage) string {
	if len(stages) == 0 {
		return emptySVG("no flow to draw yet")
	}
	width := flowMargin*2 + len(stages)*flowBoxWidth + (len(stages)-1)*flowGap
	height := flowMargin*2 + flowBoxHeight

	var b strings.Builder
	// Sized up front. A builder that doubles its buffer copies the document so
	// far on every growth, and these are rendered per page load per workload.
	b.Grow(256 + len(stages)*512)
	openSVG(&b, width, height, "Learning to enforcement flow")
	for i, st := range stages {
		x := flowMargin + i*(flowBoxWidth+flowGap)
		y := flowMargin
		class := "flow-box flow-" + stateClass(st.State)
		rect(&b, x, y, flowBoxWidth, flowBoxHeight, 8, class)
		text(&b, x+12, y+26, "flow-name", st.Name)
		text(&b, x+12, y+44, "flow-state", st.State)
		for j, line := range wrap(st.Detail, 26, 2) {
			text(&b, x+12, y+64+j*14, "flow-detail", line)
		}
		if i < len(stages)-1 {
			arrow(&b, x+flowBoxWidth, y+flowBoxHeight/2, x+flowBoxWidth+flowGap, y+flowBoxHeight/2)
		}
	}
	b.WriteString("</svg>")
	return b.String()
}

// SurfaceSVG draws the learned surface as one bar per dimension.
//
// Bars rather than a table because the shape is the finding: a workload with
// four paths and three hundred syscalls and one with three hundred paths and
// forty syscalls are different things to look at, and a column of numbers
// makes that a subtraction the reader has to perform.
func SurfaceSVG(s Surface) string {
	rows := []struct {
		label string
		count int
	}{
		{"syscalls", s.SyscallCount},
		{"file paths", s.FileCount},
		{"destinations", s.NetworkCount},
		{"executables", s.ExecutableCount},
		{"capabilities", s.CapabilityCount},
	}
	maxCount := 0
	for _, r := range rows {
		if r.count > maxCount {
			maxCount = r.count
		}
	}
	width := flowMargin*2 + barLabelCols + barTrackCols + 60
	height := flowMargin*2 + len(rows)*barRowHeight

	var b strings.Builder
	b.Grow(256 + len(rows)*256)
	openSVG(&b, width, height, "Learned surface")
	if maxCount == 0 {
		text(&b, flowMargin, flowMargin+18, "bar-empty", "nothing has been learned for this workload yet")
		b.WriteString("</svg>")
		return b.String()
	}
	for i, r := range rows {
		y := flowMargin + i*barRowHeight
		text(&b, flowMargin, y+18, "bar-label", r.label)
		rect(&b, flowMargin+barLabelCols, y+6, barTrackCols, 16, 3, "bar-track")
		// Scaled against the largest dimension rather than an absolute limit,
		// because the useful comparison is between this workload's own
		// dimensions, not against some other workload's syscall count.
		w := r.count * barTrackCols / maxCount
		if w == 0 && r.count > 0 {
			// A dimension with a handful of entries must still be visible, or
			// "two capabilities" and "no capabilities" draw identically, and
			// those are opposite findings.
			w = 2
		}
		if w > 0 {
			rect(&b, flowMargin+barLabelCols, y+6, w, 16, 3, "bar-fill")
		}
		text(&b, flowMargin+barLabelCols+barTrackCols+8, y+18, "bar-count", strconv.Itoa(r.count))
	}
	b.WriteString("</svg>")
	return b.String()
}

// ProcessTreeSVG draws what ran inside the workload, parent above child.
//
// A denied exec is only actionable if you can see what spawned it: "curl was
// denied" is a line in a log, "nginx spawned sh which spawned curl, and curl
// was denied" is an incident. The tree is the second one.
func ProcessTreeSVG(nodes []*ProcessNode, truncated bool) string {
	if len(nodes) == 0 {
		return emptySVG("no process activity has been seen for this workload")
	}
	type row struct {
		node  *ProcessNode
		depth int
		// parentRow is the row index of this node's parent, or -1 for a root.
		// The elbow connector needs the parent's y, and walking back up the
		// slice to find it would be wrong as soon as two siblings have
		// different subtree heights.
		parentRow int
	}
	rows := make([]row, 0, 32)
	var walk func(ns []*ProcessNode, depth, parent int)
	walk = func(ns []*ProcessNode, depth, parent int) {
		for _, n := range ns {
			if len(rows) >= treeMaxRows {
				return
			}
			idx := len(rows)
			rows = append(rows, row{node: n, depth: depth, parentRow: parent})
			walk(n.Children, depth+1, idx)
		}
	}
	walk(nodes, 0, -1)

	maxDepth := 0
	for _, r := range rows {
		if r.depth > maxDepth {
			maxDepth = r.depth
		}
	}
	width := flowMargin*2 + maxDepth*treeIndent + 360
	height := flowMargin*2 + len(rows)*treeRowHeight + 20

	var b strings.Builder
	b.Grow(256 + len(rows)*320)
	openSVG(&b, width, height, "Process tree")
	for i, r := range rows {
		x := flowMargin + r.depth*treeIndent
		y := flowMargin + i*treeRowHeight + 16
		if r.parentRow >= 0 {
			px := flowMargin + rows[r.parentRow].depth*treeIndent + 6
			py := flowMargin + r.parentRow*treeRowHeight + 20
			elbow(&b, px, py, x, y-5)
		}
		circle(&b, x+6, y-5, 3, nodeClass(r.node))
		label := r.node.Comm + "  x" + strconv.Itoa(r.node.Count)
		text(&b, x+18, y, "tree-label", label)
		if r.node.Denied > 0 {
			text(&b, x+18+estimateWidth(label)+8, y, "tree-denied",
				strconv.Itoa(r.node.Denied)+" denied")
		}
	}
	if truncated || len(rows) >= treeMaxRows {
		text(&b, flowMargin, flowMargin+len(rows)*treeRowHeight+18, "tree-note",
			"tree truncated; further distinct commands were folded into their parent")
	}
	b.WriteString("</svg>")
	return b.String()
}

func nodeClass(n *ProcessNode) string {
	if n.Denied > 0 {
		return "tree-dot tree-dot-denied"
	}
	return "tree-dot"
}

// estimateWidth approximates a label's rendered width. The server cannot
// measure text, so the denial marker is placed from a per-character estimate
// for the CSS font stack. Being a few pixels out pushes the marker slightly;
// being absent would put it on top of the command name.
func estimateWidth(s string) int { return len(s) * 7 }

func openSVG(b *strings.Builder, width, height int, title string) {
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `)
	writeInt(b, width)
	b.WriteByte(' ')
	writeInt(b, height)
	// width="100%" with a viewBox is what makes the diagram scale down on a
	// phone instead of forcing the page to scroll sideways.
	b.WriteString(`" width="100%" preserveAspectRatio="xMinYMin meet" role="img" aria-label="`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`"><title>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</title>`)
}

// writeInt appends a coordinate without allocating a string for it.
// strconv.Itoa allocates for anything above 99, and a diagram writes several
// hundred coordinates.
func writeInt(b *strings.Builder, v int) {
	var scratch [20]byte
	b.Write(strconv.AppendInt(scratch[:0], int64(v), 10))
}

func emptySVG(msg string) string {
	var b strings.Builder
	openSVG(&b, 420, 48, msg)
	text(&b, 8, 28, "bar-empty", msg)
	b.WriteString("</svg>")
	return b.String()
}

func rect(b *strings.Builder, x, y, w, h, r int, class string) {
	b.WriteString(`<rect x="`)
	writeInt(b, x)
	b.WriteString(`" y="`)
	writeInt(b, y)
	b.WriteString(`" width="`)
	writeInt(b, w)
	b.WriteString(`" height="`)
	writeInt(b, h)
	b.WriteString(`" rx="`)
	writeInt(b, r)
	b.WriteString(`" class="`)
	b.WriteString(html.EscapeString(class))
	b.WriteString(`"/>`)
}

func circle(b *strings.Builder, cx, cy, r int, class string) {
	b.WriteString(`<circle cx="`)
	writeInt(b, cx)
	b.WriteString(`" cy="`)
	writeInt(b, cy)
	b.WriteString(`" r="`)
	writeInt(b, r)
	b.WriteString(`" class="`)
	b.WriteString(html.EscapeString(class))
	b.WriteString(`"/>`)
}

// text writes an escaped label. Every string that reaches a diagram is a
// container's command name, a file path or an API server message, which is to
// say attacker-influenced input: a comm of "</text><script>" has to come out
// the other side as characters, not as markup.
func text(b *strings.Builder, x, y int, class, content string) {
	b.WriteString(`<text x="`)
	writeInt(b, x)
	b.WriteString(`" y="`)
	writeInt(b, y)
	b.WriteString(`" class="`)
	b.WriteString(html.EscapeString(class))
	b.WriteString(`">`)
	b.WriteString(html.EscapeString(content))
	b.WriteString(`</text>`)
}

func arrow(b *strings.Builder, x1, y1, x2, y2 int) {
	b.WriteString(`<path class="flow-arrow" d="M `)
	writeInt(b, x1)
	b.WriteByte(' ')
	writeInt(b, y1)
	b.WriteString(" L ")
	writeInt(b, x2-8)
	b.WriteByte(' ')
	writeInt(b, y2)
	b.WriteString(`"/>`)
	// The head is a filled triangle rather than a marker element, because a
	// marker needs a defs block with an id, and two diagrams in one document
	// would then collide on it.
	b.WriteString(`<path class="flow-arrow-head" d="M `)
	writeInt(b, x2-8)
	b.WriteByte(' ')
	writeInt(b, y2-5)
	b.WriteString(" L ")
	writeInt(b, x2)
	b.WriteByte(' ')
	writeInt(b, y2)
	b.WriteString(" L ")
	writeInt(b, x2-8)
	b.WriteByte(' ')
	writeInt(b, y2+5)
	b.WriteString(` Z"/>`)
}

func elbow(b *strings.Builder, x1, y1, x2, y2 int) {
	b.WriteString(`<path class="tree-line" d="M `)
	writeInt(b, x1)
	b.WriteByte(' ')
	writeInt(b, y1)
	b.WriteString(" V ")
	writeInt(b, y2)
	b.WriteString(" H ")
	writeInt(b, x2+6)
	b.WriteString(`"/>`)
}

func stateClass(state string) string {
	switch state {
	case StateDone, StateActive, StatePending, StateFailed:
		return state
	default:
		return StatePending
	}
}

// wrap breaks a detail string into at most maxLines lines of about width
// characters, on word boundaries. SVG text does not wrap by itself, so a long
// rollback reason would otherwise run straight out of its box and across the
// next one.
func wrap(s string, width, maxLines int) []string {
	if s == "" {
		return nil
	}
	words := strings.Fields(s)
	lines := make([]string, 0, maxLines)
	current := ""
	for _, word := range words {
		candidate := word
		if current != "" {
			candidate = current + " " + word
		}
		if len(candidate) > width && current != "" {
			lines = append(lines, current)
			if len(lines) == maxLines {
				// The last line gets an ellipsis so a truncated reason reads
				// as truncated rather than as a complete but odd sentence.
				lines[maxLines-1] = truncateLine(lines[maxLines-1], width)
				return lines
			}
			current = word
			continue
		}
		current = candidate
	}
	if current != "" && len(lines) < maxLines {
		lines = append(lines, current)
	}
	return lines
}

// truncateLine keeps the ellipsis inside the box. Appending "..." to a line
// that already filled the width would push the text out of the rectangle it is
// meant to be inside, which is the thing wrapping exists to prevent.
func truncateLine(s string, width int) string {
	if width < 4 {
		return s
	}
	if len(s)+3 <= width {
		return s + "..."
	}
	return s[:width-3] + "..."
}

// The diagram endpoints. They reuse the same authorisation path as the JSON
// views - the diagram is a rendering of the detail, not a second way in.

func (s *Server) handleFlowDiagram(w http.ResponseWriter, r *http.Request, access *accessChecker) {
	detail, ok := s.detailForRequest(w, r, access)
	if !ok {
		return
	}
	writeSVG(w, FlowSVG(detail.Flow))
}

func (s *Server) handleSurfaceDiagram(w http.ResponseWriter, r *http.Request, access *accessChecker) {
	detail, ok := s.detailForRequest(w, r, access)
	if !ok {
		return
	}
	writeSVG(w, SurfaceSVG(detail.Surface))
}

func (s *Server) handleTreeDiagram(w http.ResponseWriter, r *http.Request, access *accessChecker) {
	detail, ok := s.detailForRequest(w, r, access)
	if !ok {
		return
	}
	writeSVG(w, ProcessTreeSVG(detail.Processes, detail.ProcessesTruncated))
}

func writeSVG(w http.ResponseWriter, doc string) {
	w.Header().Set("Content-Type", contentTypeFor(".svg"))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(doc))
}
