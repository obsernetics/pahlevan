package tui

import (
	"context"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Cluster supplies the resources the console displays. It is an interface so
// the console can be driven from a fixture in a test, and so nothing here
// needs a Kubernetes client.
//
// Every method reads. There is no Apply, no Patch, no SetMode: the console is
// the thing an operator opens while an incident is in progress, and it must
// not be the thing that turns enforcement off by a mistyped key.
type Cluster interface {
	Policies(context.Context) ([]Policy, error)
	Profiles(context.Context) ([]Profile, error)
	AttackSurfaces(context.Context) ([]AttackSurface, error)
}

// Policy is a PahlevanPolicy reduced to what the policies view draws. It is a
// plain struct rather than the API type so pkg/tui does not depend on the
// apis package, on controller-runtime, or on a scheme registration that only
// makes sense inside the operator.
type Policy struct {
	Namespace string
	Name      string
	// Phase is the status phase verbatim: Learning, Enforcing, Failed, and so
	// on. It is a string because the console must render a phase it has never
	// heard of - a newer operator writing a new phase should show that phase,
	// not an empty cell.
	Phase string
	// Mode is the enforcement mode: Off, Monitoring, Blocking.
	Mode string
	// Selector is the rendered label selector, e.g. "app=api,tier=web".
	Selector string

	// Learning and Progress drive the progress bar. Progress is a percentage
	// and is only meaningful while Learning is true.
	Learning bool
	Progress int

	// Containers and Enforcing say how much of the selected fleet has
	// actually reached enforcement, which is the difference between a policy
	// that is working and one that merely exists.
	Containers int
	Enforcing  int

	// Denials is the in-kernel denial count across the containers this policy
	// governs.
	Denials int64

	// Rules is the resolved allow-set, one rendered rule per line, as the
	// detail pane shows it.
	Rules []string
	// Workloads names the targets the policy resolved to.
	Workloads []string

	Updated time.Time
}

// Key identifies a policy in a list and in a filter.
func (p Policy) Key() string { return p.Namespace + "/" + p.Name }

// Profile is a ContainerProfile reduced to what the profiles view draws.
type Profile struct {
	Namespace string
	Name      string
	Node      string
	Container string
	// Phase is Learning or Enforcing.
	Phase string

	Syscalls     int
	Files        int
	Network      int
	Execs        int
	Capabilities int
	Denials      int

	FirstSeen      time.Time
	EnforcingSince time.Time
}

// Key identifies a profile in a list and in a filter.
func (p Profile) Key() string { return p.Namespace + "/" + p.Name }

// Learned totals the learned entries, which is the single number that answers
// "has this container actually been observed doing anything yet".
func (p Profile) Learned() int {
	return p.Syscalls + p.Files + p.Network + p.Execs + p.Capabilities
}

// AttackSurface is an AttackSurface reduced to what its view draws.
type AttackSurface struct {
	Namespace string
	Name      string
	// Risk is the 0-100 score from the analyzer.
	Risk int

	Ports         []int32
	Syscalls      []string
	WritableFiles []string
	Capabilities  []string

	Analyzed time.Time
}

// Key identifies an attack surface in a list and in a filter.
func (a AttackSurface) Key() string { return a.Namespace + "/" + a.Name }

// Exposure counts everything the analyzer found reachable. It is the one
// number a list row can carry, with the breakdown in the detail pane.
func (a AttackSurface) Exposure() int {
	return len(a.Ports) + len(a.Syscalls) + len(a.WritableFiles) + len(a.Capabilities)
}

// Messages carrying the result of a fetch. Each one names its resource rather
// than sharing a single generic message, so Update can route a late reply to
// the right pane instead of guessing which fetch it belongs to.
type (
	policiesMsg struct {
		items []Policy
		err   error
	}
	profilesMsg struct {
		items []Profile
		err   error
	}
	surfacesMsg struct {
		items []AttackSurface
		err   error
	}
)

// resource holds one fetched list and everything the pane needs to explain
// itself: whether a fetch is running, when the last one landed, and why the
// last one failed. A failed fetch keeps the previous items, because stale data
// with a visible error beats an empty screen during an incident.
type resource[T any] struct {
	items   []T
	err     error
	loading bool
	fetched time.Time
}

// stale reports whether the list is old enough to refresh. A fetch already in
// flight is never stale: the refresh tick fires once a second and a slow API
// server would otherwise queue one request per tick forever.
func (r resource[T]) stale(now time.Time, every time.Duration) bool {
	if r.loading {
		return false
	}
	return r.fetched.IsZero() || now.Sub(r.fetched) >= every
}

// fetchTimeout bounds one cluster read. An API server that accepts the
// connection and then stops answering would otherwise leave the pane saying
// "loading" for the rest of the session, which reads as "there is nothing
// there" rather than "I cannot tell".
const fetchTimeout = 10 * time.Second

// refreshEvery is how often the cluster panes re-read. The console is a
// monitor, not a controller: often enough that a phase change shows up while
// you are looking at it, rarely enough that ten open consoles are not a load
// problem for the API server.
const refreshEvery = 5 * time.Second

// fetchPolicies reads the policies as a Bubble Tea command.
//
// The read happens on the command's own goroutine, never inside Update: a
// blocking call there freezes the event stream, the clock and the keyboard at
// once, and the first symptom is an operator thinking the agent died.
func fetchPolicies(ctx context.Context, c Cluster) tea.Cmd {
	return func() tea.Msg {
		if c == nil {
			return policiesMsg{}
		}
		ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		items, err := c.Policies(ctx)
		sort.SliceStable(items, func(i, j int) bool { return items[i].Key() < items[j].Key() })
		return policiesMsg{items: items, err: err}
	}
}

func fetchProfiles(ctx context.Context, c Cluster) tea.Cmd {
	return func() tea.Msg {
		if c == nil {
			return profilesMsg{}
		}
		ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		items, err := c.Profiles(ctx)
		sort.SliceStable(items, func(i, j int) bool { return items[i].Key() < items[j].Key() })
		return profilesMsg{items: items, err: err}
	}
}

func fetchSurfaces(ctx context.Context, c Cluster) tea.Cmd {
	return func() tea.Msg {
		if c == nil {
			return surfacesMsg{}
		}
		ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		items, err := c.AttackSurfaces(ctx)
		sort.SliceStable(items, func(i, j int) bool { return items[i].Key() < items[j].Key() })
		return surfacesMsg{items: items, err: err}
	}
}

// policyHaystack, profileHaystack and surfaceHaystack are what the filter
// matches against. As with events, the filter matches fields rather than the
// rendered row, so a match does not depend on how wide the terminal is.
func policyHaystack(p Policy) string {
	return strings.ToLower(strings.Join([]string{
		p.Namespace, p.Name, p.Phase, p.Mode, p.Selector,
		strings.Join(p.Workloads, " "),
	}, " "))
}

func profileHaystack(p Profile) string {
	return strings.ToLower(strings.Join([]string{
		p.Namespace, p.Name, p.Node, p.Container, p.Phase,
	}, " "))
}

func surfaceHaystack(a AttackSurface) string {
	return strings.ToLower(strings.Join([]string{
		a.Namespace, a.Name,
		strings.Join(a.Syscalls, " "),
		strings.Join(a.Capabilities, " "),
		strings.Join(a.WritableFiles, " "),
	}, " "))
}
