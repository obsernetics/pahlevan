package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/obsernetics/pahlevan/pkg/coverage"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// View is one of the screens the console can show.
type View int

const (
	ViewOverview View = iota
	ViewPolicies
	ViewProfiles
	ViewWorkloads
	ViewEvents
	ViewSurface
	ViewCoverage
	ViewHelp
)

// views is the tab order, and the order the number keys address. Help is not
// in it: it is a screen you open and leave, not a place you tab through.
var views = []View{
	ViewOverview, ViewPolicies, ViewProfiles, ViewWorkloads,
	ViewEvents, ViewSurface, ViewCoverage,
}

func (v View) String() string {
	switch v {
	case ViewOverview:
		return "overview"
	case ViewPolicies:
		return "policies"
	case ViewProfiles:
		return "profiles"
	case ViewWorkloads:
		return "workloads"
	case ViewEvents:
		return "events"
	case ViewSurface:
		return "attack surface"
	case ViewCoverage:
		return "coverage"
	case ViewHelp:
		return "help"
	}
	return "unknown"
}

// abbrev is the three-letter form of a view's name, for the tab strip on a
// terminal too narrow for words. Numbers alone would be shorter still, but a
// number does not tell somebody who has just opened the console what is on
// the screen they are looking at.
func (v View) abbrev() string {
	switch v {
	case ViewOverview:
		return "ovr"
	case ViewPolicies:
		return "pol"
	case ViewProfiles:
		return "prf"
	case ViewWorkloads:
		return "wkl"
	case ViewEvents:
		return "evt"
	case ViewSurface:
		return "atk"
	case ViewCoverage:
		return "cov"
	case ViewHelp:
		return "hlp"
	}
	return "?"
}

// short is the tab label when the full name does not fit. Only the attack
// surface has a name long enough to need one.
func (v View) short() string {
	if v == ViewSurface {
		return "surface"
	}
	return v.String()
}

// Messages delivered to Update.
type (
	// EventMsg carries one event from the source.
	EventMsg struct{ Event export.Event }
	// SourceEndedMsg says the source finished, with the error if it failed.
	SourceEndedMsg struct{ Err error }
	// tickMsg drives the clock in the status bar and the refresh schedule.
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

// Display names the workload the way a person reads it. The Kind is in Key
// because the key has to be unique across namespaces and kinds; in a column
// competing for width it is noise that pushes the name out.
func (w *Workload) Display() string {
	if w.Namespace == "" || w.Name == "" {
		return w.Key
	}
	return w.Namespace + "/" + w.Name
}

// deniedWhatCap bounds the per-workload denial list. The list is a hint for
// the detail pane, not an audit log; that is what the event exporters are for.
const deniedWhatCap = 12

// pane names which half of a split view the keyboard is driving.
type pane int

const (
	paneList pane = iota
	paneDetail
)

// Model is the whole console state. Update is pure with respect to it: every
// transition is a function of the model and one message, which is what makes
// the behaviour testable without a terminal.
type Model struct {
	view     View
	prevView View
	focus    pane

	// Event side.
	events     *ring
	workloads  map[string]*Workload
	order      []string
	paused     bool
	total      uint64
	denied     uint64
	sourceName string
	ended      bool
	err        error

	// Cluster side. A nil cluster is the replay case: the cluster panes say
	// so rather than sitting on an empty table that looks like a healthy
	// cluster with nothing in it.
	ctx      context.Context
	cluster  Cluster
	policies resource[Policy]
	profiles resource[Profile]
	surfaces resource[AttackSurface]

	// Cursors are per view. Tabbing away from row 40 of the profiles list and
	// back again should return to row 40, not to the top.
	cursors map[View]int
	offsets map[View]int

	// Widgets. The table is reused across views rather than one per view:
	// every view sets its own columns and its own window of rows, and seven
	// live tables would be seven viewports to keep in sync on a resize.
	tbl table.Model
	// tblCols is the column layout the table currently holds, kept so a frame
	// that changes nothing does not make the widget re-render every row.
	tblCols []table.Column
	detail  viewport.Model
	input   textinput.Model
	help    help.Model
	spin    spinner.Model
	prog    progress.Model
	keys    keyMap

	filtering bool
	spinning  bool

	// The last filter scan, kept so one frame scans the ring once.
	matched     []export.Event
	matchNeedle string
	matchGen    uint64

	width, height int
	started       time.Time
	now           func() time.Time

	// quitting short-circuits View so the final frame is not a half-drawn
	// screen left on the terminal after the program returns.
	quitting bool
}

// Options configure a Model.
type Options struct {
	// Capacity bounds retained events. Zero uses DefaultCapacity.
	Capacity int
	// SourceName is shown in the status bar.
	SourceName string
	// Cluster supplies the policy, profile and attack surface views. Nil is
	// allowed and means there is no cluster to read - `--replay`.
	Cluster Cluster
	// Context bounds the cluster reads. Zero uses context.Background.
	Context context.Context
	// Now is injectable so tests are not timing-dependent.
	Now func() time.Time
}

// DefaultCapacity is the number of events kept for the events view. A few
// thousand is more scrollback than anyone reads and small enough that the
// console's footprint does not depend on the node's syscall rate.
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
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	in := textinput.New()
	in.Prompt = "/"
	in.Placeholder = "filter"
	// Bounded because it is typed into during an incident and a pasted log
	// line should not become a filter wider than the terminal.
	in.CharLimit = 64

	sp := spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(styleAccent))

	m := &Model{
		view:       ViewOverview,
		events:     newRing(capacity),
		workloads:  map[string]*Workload{},
		cursors:    map[View]int{},
		offsets:    map[View]int{},
		ctx:        ctx,
		cluster:    opts.Cluster,
		sourceName: opts.SourceName,
		tbl:        newTable(),
		detail:     viewport.New(0, 0),
		input:      in,
		help:       newHelp(),
		spin:       sp,
		prog:       progress.New(progress.WithSolidFill("81"), progress.WithoutPercentage()),
		keys:       defaultKeys(),
		width:      80,
		height:     24,
		started:    now(),
		now:        now,
	}
	return m
}

// Init satisfies tea.Model. The tick keeps the elapsed time honest even when
// no events are arriving, which is itself information: a quiet stream and a
// dead stream look identical without a clock. It also drives the cluster
// refresh, so one timer covers both rather than three competing ones.
func (m *Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tick()}
	if c := m.refreshAll(); c != nil {
		cmds = append(cmds, c)
	}
	return tea.Batch(cmds...)
}

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
		// The refresh rides the clock tick and skips anything already in
		// flight, so a slow API server cannot queue one request per second.
		return m, tea.Batch(tick(), m.refreshStale())

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		if !m.loading() {
			// Stop animating once the fetches land. A spinner that keeps
			// ticking forces a redraw ten times a second for the rest of the
			// session, on a machine that is usually already busy.
			m.spinning = false
			return m, nil
		}
		return m, cmd

	case EventMsg:
		m.ingest(msg.Event)
		return m, nil

	case SourceEndedMsg:
		m.ended = true
		m.err = msg.Err
		return m, nil

	case policiesMsg:
		m.policies.loading = false
		m.policies.err = msg.err
		m.policies.fetched = m.now()
		if msg.err == nil {
			m.policies.items = msg.items
		}
		m.clampCursor()
		return m, nil

	case profilesMsg:
		m.profiles.loading = false
		m.profiles.err = msg.err
		m.profiles.fetched = m.now()
		if msg.err == nil {
			m.profiles.items = msg.items
		}
		m.clampCursor()
		return m, nil

	case surfacesMsg:
		m.surfaces.loading = false
		m.surfaces.err = msg.err
		m.surfaces.fetched = m.now()
		if msg.err == nil {
			m.surfaces.items = msg.items
		}
		m.clampCursor()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// loading reports whether any cluster read is in flight.
func (m *Model) loading() bool {
	return m.policies.loading || m.profiles.loading || m.surfaces.loading
}

// refreshAll starts a read of every cluster resource, regardless of age. It is
// what `r` does and what Init does.
func (m *Model) refreshAll() tea.Cmd {
	if m.cluster == nil {
		return nil
	}
	m.policies.loading = true
	m.profiles.loading = true
	m.surfaces.loading = true
	cmds := []tea.Cmd{
		fetchPolicies(m.ctx, m.cluster),
		fetchProfiles(m.ctx, m.cluster),
		fetchSurfaces(m.ctx, m.cluster),
	}
	if !m.spinning {
		m.spinning = true
		cmds = append(cmds, m.spin.Tick)
	}
	return tea.Batch(cmds...)
}

// refreshStale reads only what has aged out. Every pane draws from the same
// three lists, so the overview's counts and the policies table can never
// disagree about what the cluster said.
func (m *Model) refreshStale() tea.Cmd {
	if m.cluster == nil {
		return nil
	}
	now := m.now()
	var cmds []tea.Cmd
	if m.policies.stale(now, refreshEvery) {
		m.policies.loading = true
		cmds = append(cmds, fetchPolicies(m.ctx, m.cluster))
	}
	if m.profiles.stale(now, refreshEvery) {
		m.profiles.loading = true
		cmds = append(cmds, fetchProfiles(m.ctx, m.cluster))
	}
	if m.surfaces.stale(now, refreshEvery) {
		m.surfaces.loading = true
		cmds = append(cmds, fetchSurfaces(m.ctx, m.cluster))
	}
	if len(cmds) == 0 {
		return nil
	}
	if !m.spinning {
		m.spinning = true
		cmds = append(cmds, m.spin.Tick)
	}
	return tea.Batch(cmds...)
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
	// While the filter is focused nearly every key is text, so only the keys
	// that end the filter are read here. Typing "q" into a filter must not
	// quit the program.
	if m.filtering {
		switch {
		// ctrl+c still quits, because it is what a person reaches for when
		// they want out and it is not a character anybody means to type.
		case msg.Type == tea.KeyCtrlC:
			m.quitting = true
			return m, tea.Quit
		case msg.Type == tea.KeyEnter:
			m.filtering = false
			m.input.Blur()
		case msg.Type == tea.KeyEsc:
			m.filtering = false
			m.input.Blur()
			m.input.SetValue("")
		default:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			m.clampCursor()
			return m, cmd
		}
		m.clampCursor()
		return m, nil
	}

	switch {
	case key.Matches(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit

	case key.Matches(msg, m.keys.Jump):
		if n := int(msg.String()[0] - '1'); n >= 0 && n < len(views) {
			m.setView(views[n])
		}

	case key.Matches(msg, m.keys.Help):
		if m.view == ViewHelp {
			m.setView(m.prevView)
		} else {
			m.setView(ViewHelp)
		}

	case key.Matches(msg, m.keys.NextView):
		m.cycle(1)
	case key.Matches(msg, m.keys.PrevView):
		m.cycle(-1)

	case key.Matches(msg, m.keys.Down):
		m.scroll(1)
	case key.Matches(msg, m.keys.Up):
		m.scroll(-1)
	case key.Matches(msg, m.keys.PageDown):
		m.scroll(m.bodyHeight())
	case key.Matches(msg, m.keys.PageUp):
		m.scroll(-m.bodyHeight())
	case key.Matches(msg, m.keys.Top):
		if m.focus == paneDetail {
			m.detail.GotoTop()
		} else {
			m.setCursor(0)
		}
	case key.Matches(msg, m.keys.Bottom):
		if m.focus == paneDetail {
			m.detail.GotoBottom()
		} else {
			m.setCursor(m.rowCount() - 1)
		}

	case key.Matches(msg, m.keys.Enter):
		if m.hasDetail() && m.rowCount() > 0 {
			m.focus = paneDetail
			m.detail.GotoTop()
		}

	case key.Matches(msg, m.keys.Back):
		switch {
		case m.filterText() != "":
			m.input.SetValue("")
		case m.focus == paneDetail:
			m.focus = paneList
		case m.view == ViewHelp:
			m.setView(m.prevView)
		}

	case key.Matches(msg, m.keys.Filter):
		m.filtering = true
		m.input.SetValue("")
		m.focus = paneList
		return m, m.input.Focus()

	case key.Matches(msg, m.keys.Pause):
		m.paused = !m.paused

	case key.Matches(msg, m.keys.Clear):
		m.events.reset()

	case key.Matches(msg, m.keys.Refresh):
		m.clampCursor()
		return m, m.refreshAll()
	}

	m.clampCursor()
	return m, nil
}

// scroll moves whichever pane has the focus. With the detail pane focused the
// same keys scroll it, so a long allow-set can be read without a second set of
// bindings to remember.
func (m *Model) scroll(d int) {
	if m.focus == paneDetail && m.hasDetail() {
		if d > 0 {
			m.detail.ScrollDown(d)
		} else {
			m.detail.ScrollUp(-d)
		}
		return
	}
	m.setCursor(m.cursor() + d)
}

func (m *Model) setView(v View) {
	if v != m.view {
		m.prevView = m.view
	}
	m.view = v
	m.focus = paneList
	m.clampCursor()
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

func (m *Model) cursor() int { return m.cursors[m.view] }
func (m *Model) offset() int { return m.offsets[m.view] }

func (m *Model) setCursor(i int) {
	m.cursors[m.view] = i
	m.clampCursor()
}

// clampCursor keeps the cursor and the scroll window inside the data of the
// current view. Every path that changes the row count or the window height
// goes through here, because an off-by-one in a viewport is how a UI panics on
// a resize.
func (m *Model) clampCursor() {
	n := m.rowCount()
	cur, off := m.cursors[m.view], m.offsets[m.view]
	if n == 0 {
		m.cursors[m.view], m.offsets[m.view] = 0, 0
		return
	}
	if cur >= n {
		cur = n - 1
	}
	if cur < 0 {
		cur = 0
	}
	h := m.listHeight()
	if h < 1 {
		h = 1
	}
	if cur < off {
		off = cur
	}
	if cur >= off+h {
		off = cur - h + 1
	}
	if off > n-1 {
		off = n - 1
	}
	if off < 0 {
		off = 0
	}
	m.cursors[m.view], m.offsets[m.view] = cur, off
}

// bodyHeight is the rows available for content: the window minus the header
// and the status bar.
func (m *Model) bodyHeight() int {
	h := m.height - chromeHeight
	if h < 1 {
		return 1
	}
	return h
}

// chromeHeight is the header row plus the status row.
const chromeHeight = 2

// listHeight is the rows a table can actually fill: the body, minus its own
// column header, minus the pane border when there is room for one.
func (m *Model) listHeight() int {
	h := m.bodyHeight() - 1 // the table's column header
	if m.bordered() {
		h -= 2 // the pane's top and bottom rule
	}
	if h < 1 {
		return 1
	}
	return h
}

func (m *Model) rowCount() int {
	switch m.view {
	case ViewPolicies:
		return len(m.filteredPolicies())
	case ViewProfiles:
		return len(m.filteredProfiles())
	case ViewWorkloads:
		return len(m.filteredWorkloads())
	case ViewEvents:
		return m.eventRowCount()
	case ViewSurface:
		return len(m.filteredSurfaces())
	case ViewCoverage:
		return len(coverage.Table)
	}
	return 0
}

// hasDetail reports whether the current view has a detail pane to focus.
func (m *Model) hasDetail() bool {
	switch m.view {
	case ViewPolicies, ViewProfiles, ViewWorkloads, ViewSurface, ViewCoverage:
		return true
	}
	return false
}

func (m *Model) filterText() string { return m.input.Value() }

// filteredEvents returns the events matching the filter, oldest first.
//
// The result is cached against the filter and the ring's generation. One frame
// asks for it three times - to count the rows, to size the window and to draw
// it - and a rescan of four thousand events per ask, at the event rate, was
// most of what the console did with its CPU.
//
// Callers that only draw a window should still use filteredWindow: unfiltered,
// that reads the ring's tail without copying the rest of it.
func (m *Model) filteredEvents() []export.Event {
	needle := strings.ToLower(m.filterText())
	if needle == "" {
		return m.events.slice()
	}
	if m.matchNeedle == needle && m.matchGen == m.events.gen && m.matched != nil {
		return m.matched
	}
	out := make([]export.Event, 0, 64)
	for i := 0; i < m.events.len(); i++ {
		e, ok := m.events.at(i)
		if !ok {
			break
		}
		if strings.Contains(strings.ToLower(eventHaystack(e)), needle) {
			out = append(out, e)
		}
	}
	m.matchNeedle, m.matchGen, m.matched = needle, m.events.gen, out
	return out
}

// eventRowCount counts the rows the events view has without building them.
// Unfiltered that is the ring's length, which costs nothing; the status bar
// asks for it on every frame.
func (m *Model) eventRowCount() int {
	if m.filterText() == "" {
		return m.events.len()
	}
	return len(m.filteredEvents())
}

func (m *Model) filteredWorkloads() []*Workload {
	out := make([]*Workload, 0, len(m.order))
	needle := strings.ToLower(m.filterText())
	for _, k := range m.order {
		if needle != "" && !strings.Contains(strings.ToLower(k), needle) {
			continue
		}
		out = append(out, m.workloads[k])
	}
	return out
}

func (m *Model) filteredPolicies() []Policy {
	needle := strings.ToLower(m.filterText())
	if needle == "" {
		return m.policies.items
	}
	out := make([]Policy, 0, len(m.policies.items))
	for _, p := range m.policies.items {
		if strings.Contains(policyHaystack(p), needle) {
			out = append(out, p)
		}
	}
	return out
}

func (m *Model) filteredProfiles() []Profile {
	needle := strings.ToLower(m.filterText())
	if needle == "" {
		return m.profiles.items
	}
	out := make([]Profile, 0, len(m.profiles.items))
	for _, p := range m.profiles.items {
		if strings.Contains(profileHaystack(p), needle) {
			out = append(out, p)
		}
	}
	return out
}

func (m *Model) filteredSurfaces() []AttackSurface {
	needle := strings.ToLower(m.filterText())
	if needle == "" {
		return m.surfaces.items
	}
	out := make([]AttackSurface, 0, len(m.surfaces.items))
	for _, a := range m.surfaces.items {
		if strings.Contains(surfaceHaystack(a), needle) {
			out = append(out, a)
		}
	}
	return out
}

// Elapsed reports how long the console has been running, measured from the
// injected clock so a test is not timing-dependent.
func (m *Model) Elapsed(now time.Time) time.Duration { return now.Sub(m.started) }

// Stream wires a Source into the Bubble Tea program. It owns the goroutine so
// a caller cannot leak one, and it reports the end of the stream as a message
// rather than silently stopping, because a console that stops updating without
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
