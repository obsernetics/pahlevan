package export

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capture records what a notifier POSTed, so assertions are about the request
// a destination would actually receive.
type capture struct {
	mu     sync.Mutex
	bodies []string
	status int
	reply  string
}

func (c *capture) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, string(b))
		c.mu.Unlock()
		if c.status != 0 {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.reply))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func (c *capture) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.bodies))
	copy(out, c.bodies)
	return out
}

func denial(path, ns, workload string, at time.Time) *Event {
	return &Event{
		Version:   "pahlevan.io/v1alpha1",
		Timestamp: Timestamp(at),
		Type:      EventTypeFile,
		Action:    ActionDeny,
		Process:   ProcessInfo{PID: 42, Comm: "python3"},
		CgroupID:  99,
		File:      &FileInfo{Path: path},
		Kubernetes: &KubernetesRef{
			Namespace: ns, Pod: workload + "-abc123",
			WorkloadKind: "Deployment", WorkloadName: workload,
		},
	}
}

func observation(path string) *Event {
	e := denial(path, "prod", "web", time.Unix(1700000000, 0))
	e.Action = ActionObserve
	return e
}

// An observation stream is not an alert stream. A channel receiving one message
// per file open is a channel that gets muted within the hour, so denials only
// is the default and it has to actually hold.
func TestNotifiersSendDenialsOnlyByDefault(t *testing.T) {
	c := &capture{}
	srv := c.server(t)

	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1})
	require.NoError(t, err)
	require.NoError(t, s.Export(context.Background(), []*Event{observation("/etc/nginx/nginx.conf")}))
	assert.Zero(t, c.count(), "an observation must not produce a Slack message")

	require.NoError(t, s.Export(context.Background(),
		[]*Event{denial("/etc/shadow", "prod", "web", time.Unix(1700000000, 0))}))
	assert.Equal(t, 1, c.count(), "a denial must produce a message")
}

func TestAllEventsOptIn(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, AllEvents: true, DedupeWindow: -1})
	require.NoError(t, err)
	require.NoError(t, s.Export(context.Background(), []*Event{observation("/etc/nginx/nginx.conf")}))
	assert.Equal(t, 1, c.count(), "AllEvents must deliver observations too")
}

// A crash-looping pod denied the same path produces one denial per restart. The
// fortieth identical message tells nobody anything the first did not.
func TestDedupeSuppressesTheSameFindingWithinTheWindow(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: time.Minute})
	require.NoError(t, err)

	base := time.Unix(1700000000, 0)
	now := base
	s.dedupe.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		// Different pid and timestamp each time: the same finding regardless.
		ev := denial("/etc/shadow", "prod", "web", now)
		ev.Process.PID = uint32(1000 + i)
		require.NoError(t, s.Export(context.Background(), []*Event{ev}))
		now = now.Add(5 * time.Second)
	}
	assert.Equal(t, 1, c.count(), "five occurrences of one finding must send one message")

	// Past the window it is news again.
	now = base.Add(2 * time.Minute)
	require.NoError(t, s.Export(context.Background(), []*Event{denial("/etc/shadow", "prod", "web", now)}))
	assert.Equal(t, 2, c.count(), "the same finding after the window must send again")
}

// The workload, not the pod: a Deployment rolling out gives every replica a new
// pod name, and one message per replica for one misconfiguration is exactly the
// noise deduplication exists to stop.
func TestDedupeKeysOnTheWorkloadNotThePod(t *testing.T) {
	a := denial("/etc/shadow", "prod", "web", time.Unix(1700000000, 0))
	a.Kubernetes.Pod = "web-abc123"
	b := denial("/etc/shadow", "prod", "web", time.Unix(1700000060, 0))
	b.Kubernetes.Pod = "web-xyz789"
	assert.Equal(t, FindingKey(a), FindingKey(b),
		"two replicas of one Deployment denied the same path are one finding")

	other := denial("/etc/shadow", "prod", "api", time.Unix(1700000000, 0))
	assert.NotEqual(t, FindingKey(a), FindingKey(other),
		"different workloads are different findings")

	diff := denial("/etc/passwd", "prod", "web", time.Unix(1700000000, 0))
	assert.NotEqual(t, FindingKey(a), FindingKey(diff),
		"different paths are different findings")
}

func TestDedupeCanBeDisabled(t *testing.T) {
	d := newDedupe(-1)
	for i := 0; i < 10; i++ {
		assert.True(t, d.allow("same"), "a negative window must not suppress anything")
	}
}

func TestDedupeEvictsExpiredEntries(t *testing.T) {
	d := newDedupe(time.Minute)
	now := time.Unix(1700000000, 0)
	d.now = func() time.Time { return now }
	for i := 0; i < 4200; i++ {
		d.allow(string(rune(i)) + "key")
	}
	// Past the window, one more insert triggers the sweep.
	now = now.Add(2 * time.Minute)
	d.allow("trigger")
	d.mu.Lock()
	n := len(d.seen)
	d.mu.Unlock()
	assert.Less(t, n, 4200, "expired entries must be evicted, or the map grows forever")
}

// A batch becomes one message describing all of it, not one message each.
func TestSlackGroupsABatchIntoOneMessage(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1, Source: "node-1"})
	require.NoError(t, err)

	base := time.Unix(1700000000, 0)
	require.NoError(t, s.Export(context.Background(), []*Event{
		denial("/etc/shadow", "prod", "web", base),
		denial("/tmp/xmrig", "prod", "web", base.Add(time.Second)),
		denial("/root/.ssh/id_rsa", "prod", "api", base.Add(2*time.Second)),
	}))
	require.Equal(t, 1, c.count())

	var p slackPayload
	require.NoError(t, json.Unmarshal([]byte(c.all()[0]), &p))
	assert.Contains(t, p.Text, "denied 3 operations")
	assert.Contains(t, p.Text, "node-1")
	// A header plus one section per finding.
	assert.Len(t, p.Blocks, 4)
	body := c.all()[0]
	for _, want := range []string{"/etc/shadow", "/tmp/xmrig", "/root/.ssh/id_rsa"} {
		assert.Contains(t, body, want)
	}
}

// The fallback text is the push notification. Without it a phone at 3am shows
// "attachment", which is useless.
func TestSlackAlwaysSetsFallbackText(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1})
	require.NoError(t, err)
	require.NoError(t, s.Export(context.Background(),
		[]*Event{denial("/etc/shadow", "prod", "web", time.Unix(1700000000, 0))}))

	var p slackPayload
	require.NoError(t, json.Unmarshal([]byte(c.all()[0]), &p))
	assert.NotEmpty(t, p.Text, "the fallback text is the push notification")
}

func TestSlackCapsFindingsAndSaysHowManyMore(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1, MaxPerMessage: 2})
	require.NoError(t, err)

	base := time.Unix(1700000000, 0)
	var batch []*Event
	for i := 0; i < 5; i++ {
		batch = append(batch, denial("/tmp/x"+string(rune('a'+i)), "prod", "web", base.Add(time.Duration(i)*time.Second)))
	}
	require.NoError(t, s.Export(context.Background(), batch))

	body := c.all()[0]
	assert.Contains(t, body, "and 3 more in this batch",
		"the findings beyond the cap must be counted, not dropped silently")
}

// PagerDuty's model is an incident per problem. Folding four unrelated denials
// into one incident means resolving it resolves all four.
func TestPagerDutyRaisesOneIncidentPerFinding(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	p, err := NewPagerDutyNotifier(PagerDutyOptions{
		NotifyOptions: NotifyOptions{URL: srv.URL, DedupeWindow: -1},
		RoutingKey:    "rk",
	})
	require.NoError(t, err)

	base := time.Unix(1700000000, 0)
	require.NoError(t, p.Export(context.Background(), []*Event{
		denial("/etc/shadow", "prod", "web", base),
		denial("/tmp/xmrig", "prod", "api", base.Add(time.Second)),
	}))
	assert.Equal(t, 2, c.count(), "two distinct findings are two incidents")

	var ev pagerDutyEvent
	require.NoError(t, json.Unmarshal([]byte(c.all()[0]), &ev))
	assert.Equal(t, "rk", ev.RoutingKey)
	assert.Equal(t, "trigger", ev.EventAction)
	assert.Equal(t, "error", ev.Payload.Severity)
	// The dedup key is the finding, so the same problem re-triggers the same
	// incident rather than opening a second one.
	assert.Equal(t, FindingKey(denial("/etc/shadow", "prod", "web", base)), ev.DedupKey)
	// Source is the workload: somebody paged at 3am needs the service, not the node.
	assert.Contains(t, ev.Payload.Source, "web")
}

func TestPagerDutySeverityIsValidated(t *testing.T) {
	_, err := NewPagerDutyNotifier(PagerDutyOptions{
		NotifyOptions: NotifyOptions{URL: "http://x"}, RoutingKey: "rk", Severity: "urgent",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical, error, warning, info")

	for _, s := range []string{"critical", "error", "warning", "info", ""} {
		_, err := NewPagerDutyNotifier(PagerDutyOptions{
			NotifyOptions: NotifyOptions{URL: "http://x"}, RoutingKey: "rk", Severity: s,
		})
		assert.NoError(t, err, "severity %q must be accepted", s)
	}
}

func TestPagerDutyNeedsARoutingKey(t *testing.T) {
	_, err := NewPagerDutyNotifier(PagerDutyOptions{NotifyOptions: NotifyOptions{URL: "http://x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "routing key")
}

func TestPagerDutyDefaultsToTheEventsAPI(t *testing.T) {
	p, err := NewPagerDutyNotifier(PagerDutyOptions{RoutingKey: "rk"})
	require.NoError(t, err)
	assert.Equal(t, DefaultPagerDutyURL, p.opts.URL)
}

func TestTemplateNotifierRendersAndPosts(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	n, err := NewTemplateNotifier(TemplateOptions{
		NotifyOptions: NotifyOptions{URL: srv.URL, DedupeWindow: -1, Source: "node-1"},
		Template: `{"title":{{ .Summary | json }},"items":[` +
			`{{ range $i, $e := .Events }}{{ if $i }},{{ end }}{{ summary $e | json }}{{ end }}]}`,
		Headers: map[string]string{"X-Api-Key": "secret"},
	})
	require.NoError(t, err)

	base := time.Unix(1700000000, 0)
	require.NoError(t, n.Export(context.Background(), []*Event{
		denial("/etc/shadow", "prod", "web", base),
		denial("/tmp/xmrig", "prod", "web", base.Add(time.Second)),
	}))
	require.Equal(t, 1, c.count())

	var got struct {
		Title string   `json:"title"`
		Items []string `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(c.all()[0]), &got),
		"the rendered body must be valid JSON")
	assert.Contains(t, got.Title, "denied 2 operations")
	assert.Len(t, got.Items, 2)
	assert.Contains(t, got.Items[0], "/etc/shadow")
}

// A path containing a quote is what breaks a naive template the first time it
// meets real data, which is why the json helper exists.
func TestTemplateJSONHelperEscapes(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	n, err := NewTemplateNotifier(TemplateOptions{
		NotifyOptions: NotifyOptions{URL: srv.URL, DedupeWindow: -1},
		Template:      `{"path":{{ subject (index .Events 0) | json }}}`,
	})
	require.NoError(t, err)
	require.NoError(t, n.Export(context.Background(),
		[]*Event{denial(`/tmp/a"b\c`, "prod", "web", time.Unix(1700000000, 0))}))

	var got map[string]string
	require.NoError(t, json.Unmarshal([]byte(c.all()[0]), &got),
		"a quote in a path must not produce invalid JSON")
	assert.Equal(t, `/tmp/a"b\c`, got["path"])
}

// A syntax error must fail at construction, naming the mistake - not once per
// batch while notifications silently never arrive.
func TestTemplateSyntaxErrorFailsAtConstruction(t *testing.T) {
	_, err := NewTemplateNotifier(TemplateOptions{
		NotifyOptions: NotifyOptions{URL: "http://x"},
		Template:      `{{ range .Events }}unclosed`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing the notification template")
}

func TestNotifiersValidateTheirRequiredFields(t *testing.T) {
	_, err := NewSlackNotifier(NotifyOptions{})
	assert.ErrorContains(t, err, "incoming-webhook URL")

	_, err = NewTemplateNotifier(TemplateOptions{NotifyOptions: NotifyOptions{URL: "http://x"}})
	assert.ErrorContains(t, err, "needs a template")

	_, err = NewTemplateNotifier(TemplateOptions{Template: "x"})
	assert.ErrorContains(t, err, "needs a URL")
}

// The body of a rejected notification says what is wrong - an expired webhook,
// a bad routing key. Discarding it leaves an operator with a bare status code.
func TestRejectionCarriesTheDestinationsExplanation(t *testing.T) {
	c := &capture{status: http.StatusForbidden, reply: "invalid_token"}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1})
	require.NoError(t, err)

	err = s.Export(context.Background(),
		[]*Event{denial("/etc/shadow", "prod", "web", time.Unix(1700000000, 0))})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "invalid_token")
}

func TestClosedNotifiersRefuse(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	ev := []*Event{denial("/etc/shadow", "prod", "web", time.Unix(1700000000, 0))}

	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1})
	require.NoError(t, err)
	require.NoError(t, s.Close())
	assert.ErrorIs(t, s.Export(context.Background(), ev), ErrClosed)

	p, err := NewPagerDutyNotifier(PagerDutyOptions{
		NotifyOptions: NotifyOptions{URL: srv.URL, DedupeWindow: -1}, RoutingKey: "rk"})
	require.NoError(t, err)
	require.NoError(t, p.Close())
	assert.ErrorIs(t, p.Export(context.Background(), ev), ErrClosed)

	n, err := NewTemplateNotifier(TemplateOptions{
		NotifyOptions: NotifyOptions{URL: srv.URL, DedupeWindow: -1}, Template: "x"})
	require.NoError(t, err)
	require.NoError(t, n.Close())
	assert.ErrorIs(t, n.Export(context.Background(), ev), ErrClosed)

	// Close is idempotent, like every other sink.
	assert.NoError(t, s.Close())
}

func TestEmptyAndNilBatchesAreNoOps(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1})
	require.NoError(t, err)

	require.NoError(t, s.Export(context.Background(), nil))
	require.NoError(t, s.Export(context.Background(), []*Event{}))
	require.NoError(t, s.Export(context.Background(), []*Event{nil, nil}))
	assert.Zero(t, c.count(), "nothing to report must send nothing")
}

// A message that reads in the order things happened is one somebody can follow.
func TestFindingsAreOrderedOldestFirst(t *testing.T) {
	base := time.Unix(1700000000, 0)
	out := selectFindings([]*Event{
		denial("/c", "prod", "web", base.Add(2*time.Second)),
		denial("/a", "prod", "web", base),
		denial("/b", "prod", "web", base.Add(time.Second)),
	}, false, nil)
	require.Len(t, out, 3)
	assert.Equal(t, "/a", out[0].File.Path)
	assert.Equal(t, "/b", out[1].File.Path)
	assert.Equal(t, "/c", out[2].File.Path)
}

func TestFindingSubjectAndWorkloadCoverEveryEventShape(t *testing.T) {
	base := time.Unix(1700000000, 0)
	file := denial("/etc/shadow", "prod", "web", base)
	assert.Equal(t, "/etc/shadow", FindingSubject(file))
	assert.Contains(t, WorkloadOf(file), "Deployment/web in prod")

	net := &Event{Network: &NetworkInfo{DestinationIP: "10.0.0.1", DestinationPort: 5432}}
	assert.Equal(t, "10.0.0.1:5432", FindingSubject(net))
	named := &Event{Network: &NetworkInfo{DestinationName: "prod/postgres", DestinationPort: 5432}}
	assert.Equal(t, "prod/postgres:5432", FindingSubject(named))

	assert.Equal(t, "/tmp/xmrig", FindingSubject(&Event{Exec: &ExecInfo{Binary: "/tmp/xmrig"}}))
	assert.Equal(t, "CAP_SYS_ADMIN", FindingSubject(&Event{Capability: &CapabilityInfo{Name: "CAP_SYS_ADMIN"}}))
	assert.Equal(t, "ptrace", FindingSubject(&Event{Syscall: &SyscallInfo{Name: "ptrace"}}))

	// No Kubernetes attribution yet: fall back to the cgroup rather than blank.
	assert.Contains(t, WorkloadOf(&Event{CgroupID: 77}), "cgroup 77")
	// Pod without an owning workload.
	podOnly := &Event{Kubernetes: &KubernetesRef{Namespace: "prod", Pod: "loose"}}
	assert.Equal(t, "prod/loose", WorkloadOf(podOnly))

	assert.Empty(t, FindingSubject(nil))
	assert.Empty(t, WorkloadOf(nil))
	assert.Empty(t, FindingKey(nil))
}

func TestTruncateMarksWhatItCut(t *testing.T) {
	assert.Equal(t, "abc", Truncate("abc", 5))
	assert.Equal(t, "abc", Truncate("abc", 3))
	assert.Equal(t, "ab…", Truncate("abcdef", 3))
	assert.Equal(t, "abcdef", Truncate("abcdef", 0))
	assert.Equal(t, "a", Truncate("abcdef", 1))
}

// The exec command line is the difference between "python3 was denied" and
// knowing what it was asked to run.
func TestSlackIncludesTheCommandLine(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1})
	require.NoError(t, err)

	ev := denial("", "prod", "web", time.Unix(1700000000, 0))
	ev.Type = EventTypeProcess
	ev.File = nil
	ev.Exec = &ExecInfo{Binary: "/usr/bin/python3", CommandLine: "python3 -c import socket;..."}
	require.NoError(t, s.Export(context.Background(), []*Event{ev}))
	assert.Contains(t, c.all()[0], "import socket")
}

func TestNotifiersAreSafeUnderConcurrentExport(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	s, err := NewSlackNotifier(NotifyOptions{URL: srv.URL, DedupeWindow: -1})
	require.NoError(t, err)

	base := time.Unix(1700000000, 0)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = s.Export(context.Background(),
				[]*Event{denial("/tmp/"+strings.Repeat("x", i+1), "prod", "web", base)})
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 20, c.count())
}

func BenchmarkFindingKey(b *testing.B) {
	ev := denial("/etc/shadow", "prod", "web", time.Unix(1700000000, 0))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FindingKey(ev)
	}
}

func BenchmarkDedupeAllowHit(b *testing.B) {
	d := newDedupe(time.Minute)
	d.allow("k")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.allow("k")
	}
}

func BenchmarkSelectFindings(b *testing.B) {
	base := time.Unix(1700000000, 0)
	batch := make([]*Event, 0, 256)
	for i := 0; i < 256; i++ {
		ev := denial("/tmp/x", "prod", "web", base.Add(time.Duration(i)*time.Millisecond))
		if i%2 == 0 {
			ev.Action = ActionObserve
		}
		batch = append(batch, ev)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = selectFindings(batch, false, nil)
	}
}

func BenchmarkSlackPayload(b *testing.B) {
	s, _ := NewSlackNotifier(NotifyOptions{URL: "http://x", DedupeWindow: -1})
	base := time.Unix(1700000000, 0)
	findings := []*Event{
		denial("/etc/shadow", "prod", "web", base),
		denial("/tmp/xmrig", "prod", "web", base.Add(time.Second)),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.payload(findings)
	}
}
