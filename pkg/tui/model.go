package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// View is one of the screens the UI can show.
type View int

const (
	ViewEvents View = iota
	ViewWorkloads
	ViewDetail
	ViewCoverage
	ViewHelp
)

// views is the tab order. Detail is reachable only by selecting a workload,
// so it is not in the cycle: tabbing into a screen that says "nothing
// selected" is a dead end the user has to back out of.
var views = []View{ViewEvents, ViewWorkloads, ViewCoverage, ViewHelp}

func (v View) String() string {
	switch v {
	case ViewEvents:
		return "events"
	case ViewWorkloads:
		return "workloads"
	case ViewDetail:
		return "detail"
	case ViewCoverage:
		return "coverage"
	case ViewHelp:
		return "help"
	}
	return "unknown"
}

// Messages delivered to Update.
type (
	// EventMsg carries one event from the source.
	EventMsg struct{ Event export.Event }
	// SourceEndedMsg says the source finished, with the error if it failed.
	SourceEndedMsg struct{ Err error }
	// tickMsg drives the clock in the status line.
	tickMsg time.Time
)

// Workload aggregates what has been seen for one owning workload.
//
// Keyed by workload rather than by pod: a Deployment rolling out replaces
// every pod name, and an operator watching a rollout does not want the
// history to reset because the replica set changed.
type Workload struct {
	Key       string
	Namespace string
	Kind      string
	Name      string
	Node      string

	Files      int
	Network    int
	Execs      int
	Caps       int
	Syscalls   int
	Denials    int
	LastSeen   time.Time
	DeniedWhat []string // most recent denial descriptions, bounded
}

// deniedWhatCap bounds the per-workload denial list. The list is a hint for
// the detail pane, not an audit log; that is what the event exporters are for.
const deniedWhatCap = 12

// Model is the whole UI state. Update is pure with respect to it: every
// transition is a function of the model and one message, which is what makes
// the behaviour testable without a terminal.
type Model struct {
	view     View
	prevView View

	events    *ring
	workloads map[string]*Workload
	order     []string

	cursor   int
	offset   int
	selected string

	paused bool
	filter string
	typing bool

	width, height int

	sourceName string
	ended      bool
	err        error
	started    time.Time
	total      uint64
	denied     uint64

	// quitting short-circuits View so the final frame is not a half-drawn
	// screen left on the terminal after the program returns.
	quitting bool
}

// Options configure a Model.
type Options struct {
	// Capacity bounds retained events. Zero uses DefaultCapacity.
	Capacity int
	// SourceName is shown in the status line.
	SourceName string
	// Now is injectable so tests are not timing-dependent.
	Now func() time.Time
}

// DefaultCapacity is the number of events kept for the events view. A few
// thousand is more scrollback than anyone reads and small enough that the UI's
// footprint does not depend on the node's syscall rate.
const DefaultCapacity = 4096

var nowFn = time.Now

// New builds a Model.
func New(opts Options) *Model {
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	now := opts.Now
	if now == nil {
		now = nowFn
	}
	return &Model{
		view:       ViewEvents,
		events:     newRing(capacity),
		workloads:  map[string]*Workload{},
		sourceName: opts.SourceName,
		started:    now(),
		width:      80,
		height:     24,
	}
}

// Init satisfies tea.Model. The tick keeps the elapsed time honest even when
// no events are arriving, which is itself information: a quiet stream and a
// dead stream look identical without a clock.
func (m *Model) Init() tea.Cmd { return tick() }

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Update advances the model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.clampCursor()
		return m, nil

	case tickMsg:
		return m, tick()

	case EventMsg:
		m.ingest(msg.Event)
		return m, nil

	case SourceEndedMsg:
		m.ended = true
		m.err = msg.Err
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// ingest folds one event into the model. Paused freezes the event list but not
// the counters: an operator pauses to read a line, and returning to a view
// that pretended nothing happened meanwhile would be a lie.
func (m *Model) ingest(e export.Event) {
	m.total++
	if e.Denied() {
		m.denied++
	}
	if !m.paused {
		m.events.push(e)
	}
	m.foldWorkload(e)
}

func (m *Model) foldWorkload(e export.Event) {
	key := workloadKey(e)
	w, ok := m.workloads[key]
	if !ok {
		w = &Workload{Key: key}
		if k := e.Kubernetes; k != nil {
			w.Namespace, w.Kind, w.Name, w.Node = k.Namespace, k.WorkloadKind, k.WorkloadName, k.Node
			if w.Name == "" {
				w.Name = k.Pod
			}
		}
		m.workloads[key] = w
		m.order = append(m.order, key)
		sort.Strings(m.order)
	}
	switch e.Type {
	case export.EventTypeFile:
		w.Files++
	case export.EventTypeNetwork:
		w.Network++
	case export.EventTypeProcess:
		w.Execs++
	case export.EventTypeCapability:
		w.Caps++
	case export.EventTypeSyscall:
		w.Syscalls++
	}
	if e.Denied() {
		w.Denials++
		if d := describeEvent(e); d != "" {
			w.DeniedWhat = append(w.DeniedWhat, d)
			if len(w.DeniedWhat) > deniedWhatCap {
				w.DeniedWhat = w.DeniedWhat[len(w.DeniedWhat)-deniedWhatCap:]
			}
		}
	}
	w.LastSeen = e.Timestamp.Time()
}

// workloadKey identifies the owner of an event. Events with no Kubernetes
// attribution are grouped under their cgroup rather than dropped: on a node
// running things Pahlevan cannot attribute, showing them as unattributed is
// more useful than not showing them.
func workloadKey(e export.Event) string {
	k := e.Kubernetes
	if k == nil {
		return fmt.Sprintf("cgroup:%d", e.CgroupID)
	}
	switch {
	case k.WorkloadKind != "" && k.WorkloadName != "":
		return k.Namespace + "/" + k.WorkloadKind + "/" + k.WorkloadName
	case k.Pod != "":
		return k.Namespace + "/Pod/" + k.Pod
	default:
		return fmt.Sprintf("cgroup:%d", e.CgroupID)
	}
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// While typing a filter, most keys are text.
	if m.typing {
		switch msg.Type {
		case tea.KeyEnter, tea.KeyEsc:
			m.typing = false
			if msg.Type == tea.KeyEsc {
				m.filter = ""
			}
		case tea.KeyBackspace:
			if n := len(m.filter); n > 0 {
				m.filter = m.filter[:n-1]
			}
		case tea.KeyCtrlC:
			m.quitting = true
			return m, tea.Quit
		case tea.KeyRunes, tea.KeySpace:
			m.filter += string(msg.Runes)
			if msg.Type == tea.KeySpace {
				m.filter += " "
			}
		}
		m.clampCursor()
		return m, nil
	}

	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "tab", "l", "right":
		m.cycle(1)
	case "shift+tab", "h", "left":
		m.cycle(-1)
	case "1":
		m.setView(ViewEvents)
	case "2":
		m.setView(ViewWorkloads)
	case "3":
		m.setView(ViewCoverage)
	case "?":
		m.setView(ViewHelp)
	case "j", "down":
		m.moveCursor(1)
	case "k", "up":
		m.moveCursor(-1)
	case "pgdown", "ctrl+f":
		m.moveCursor(m.bodyHeight())
	case "pgup", "ctrl+b":
		m.moveCursor(-m.bodyHeight())
	case "g", "home":
		m.cursor = 0
		m.offset = 0
	case "G", "end":
		m.cursor = m.rowCount() - 1
		m.clampCursor()
	case " ":
		m.paused = !m.paused
	case "/":
		m.typing = true
		m.filter = ""
	case "esc":
		switch {
		case m.filter != "":
			m.filter = ""
		case m.view == ViewDetail || m.view == ViewHelp:
			m.setView(m.prevView)
		}
	case "enter":
		if m.view == ViewWorkloads {
			if k, ok := m.workloadAt(m.cursor); ok {
				m.selected = k
				m.setView(ViewDetail)
			}
		}
	case "c":
		m.events.reset()
		m.clampCursor()
	}
	m.clampCursor()
	return m, nil
}

func (m *Model) setView(v View) {
	if v != m.view {
		m.prevView = m.view
	}
	m.view = v
	m.cursor, m.offset = 0, 0
}

func (m *Model) cycle(d int) {
	cur := 0
	for i, v := range views {
		if v == m.view {
			cur = i
		}
	}
	next := views[((cur+d)%len(views)+len(views))%len(views)]
	m.setView(next)
}

func (m *Model) moveCursor(d int) {
	m.cursor += d
	m.clampCursor()
}

// clampCursor keeps the cursor and the scroll window inside the data. Every
// path that changes the row count or the window height goes through here,
// because an off-by-one in a viewport is how a UI panics on a resize.
func (m *Model) clampCursor() {
	n := m.rowCount()
	if n == 0 {
		m.cursor, m.offset = 0, 0
		return
	}
	if m.cursor >= n {
		m.cursor = n - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	h := m.bodyHeight()
	if h < 1 {
		h = 1
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+h {
		m.offset = m.cursor - h + 1
	}
	if m.offset > n-1 {
		m.offset = n - 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

// bodyHeight is the rows available for content: the window minus the header
// and the status line.
func (m *Model) bodyHeight() int {
	h := m.height - chromeHeight
	if h < 1 {
		return 1
	}
	return h
}

// chromeHeight is the header plus status line plus their separators.
const chromeHeight = 4

func (m *Model) rowCount() int {
	switch m.view {
	case ViewEvents:
		return len(m.filteredEvents())
	case ViewWorkloads:
		return len(m.filteredWorkloads())
	case ViewDetail:
		if w := m.selectedWorkload(); w != nil {
			return len(w.DeniedWhat)
		}
		return 0
	}
	return 0
}

// filteredEvents returns the events matching the filter, oldest first.
//
// Callers that only draw a window should use filteredWindow: this copies the
// whole ring, and a redraw happens per event, so on a busy node it is the
// dominant cost in the UI.
func (m *Model) filteredEvents() []export.Event {
	all := m.events.slice()
	if m.filter == "" {
		return all
	}
	needle := strings.ToLower(m.filter)
	out := all[:0:0]
	for _, e := range all {
		if strings.Contains(strings.ToLower(eventHaystack(e)), needle) {
			out = append(out, e)
		}
	}
	return out
}

// filteredWindow returns at most n of the newest matching events.
//
// Unfiltered, this reads the tail of the ring directly instead of copying all
// of it: at the default capacity a full copy was 413KB and 330us per frame,
// once per event, which is a lot of work to render twenty lines.
func (m *Model) filteredWindow(n int) []export.Event {
	if m.filter == "" {
		return m.events.last(n)
	}
	all := m.filteredEvents()
	if len(all) > n {
		return all[len(all)-n:]
	}
	return all
}

func (m *Model) filteredWorkloads() []*Workload {
	out := make([]*Workload, 0, len(m.order))
	needle := strings.ToLower(m.filter)
	for _, k := range m.order {
		w := m.workloads[k]
		if needle != "" && !strings.Contains(strings.ToLower(k), needle) {
			continue
		}
		out = append(out, w)
	}
	return out
}

func (m *Model) workloadAt(i int) (string, bool) {
	ws := m.filteredWorkloads()
	if i < 0 || i >= len(ws) {
		return "", false
	}
	return ws[i].Key, true
}

func (m *Model) selectedWorkload() *Workload { return m.workloads[m.selected] }

// Stream wires a Source into the Bubble Tea program. It owns the goroutine so
// a caller cannot leak one, and it reports the end of the stream as a message
// rather than silently stopping, because a UI that stops updating without
// saying why is indistinguishable from a hung one.
func Stream(ctx context.Context, src Source, send func(tea.Msg)) {
	ch := make(chan export.Event, 256)
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, ch); close(ch) }()
	go func() {
		for e := range ch {
			send(EventMsg{Event: e})
		}
		send(SourceEndedMsg{Err: <-done})
	}()
}
