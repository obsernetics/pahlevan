package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"
)

// Formatted delivery of denials to the places people actually look.
//
// The webhook sink POSTs the raw event envelope, which is the right shape for
// a collector and the wrong shape for a human: nobody reads a JSON array in a
// chat client. Getting a denial in front of the person who can act on it meant
// writing a small reshaping service, which every operator was building
// separately and none of them wanted to.
//
// So: Slack, PagerDuty, and a template you fill in yourself for everything
// else. All three are Exporters, so they compose with the queue, batching and
// drop-counting the other sinks already use rather than sitting beside it.
//
// Three properties they share, because a notifier without them makes the
// on-call experience worse rather than better:
//
//   - Denials only, by default. An observation stream is not an alert stream,
//     and a channel that receives one message per file open gets muted within
//     the hour.
//   - Deduplicated over a window. A crash-looping pod denied the same path
//     produces one denial per restart, and the fortieth identical message
//     tells nobody anything the first did not.
//   - Grouped per delivery. A batch becomes one message describing all of it,
//     not one message each.

// Notifier defaults.
const (
	// DefaultDedupeWindow is how long an identical finding stays suppressed.
	DefaultDedupeWindow = 5 * time.Minute
	// DefaultMaxPerMessage caps how many findings one message describes.
	DefaultMaxPerMessage = 10
	// DefaultPagerDutyURL is the Events API v2 endpoint.
	DefaultPagerDutyURL = "https://events.pagerduty.com/v2/enqueue"
)

// NotifyOptions is the configuration common to every notifier.
type NotifyOptions struct {
	// URL is the destination. Required.
	URL string
	// Timeout bounds one HTTP attempt. Zero uses DefaultWebhookTimeout.
	Timeout time.Duration
	// Client overrides the HTTP client, for tests and proxied setups.
	Client *http.Client
	// Source names the sending agent, normally the node name.
	Source string

	// AllEvents delivers observations as well as denials.
	//
	// Off by default. A busy node produces thousands of file events a minute
	// and a chat channel receiving them is a channel nobody reads.
	AllEvents bool

	// DedupeWindow suppresses a repeat of an identical finding: same workload,
	// same kind of operation, same subject.
	//
	// Zero uses DefaultDedupeWindow. Negative disables deduplication, which is
	// occasionally what an audit trail wants.
	DedupeWindow time.Duration

	// MaxPerMessage caps the findings described before the rest become a
	// count. Zero uses DefaultMaxPerMessage.
	MaxPerMessage int
}

func (o NotifyOptions) httpClient() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	t := o.Timeout
	if t <= 0 {
		t = DefaultWebhookTimeout
	}
	return &http.Client{Timeout: t}
}

func (o NotifyOptions) maxPerMessage() int {
	if o.MaxPerMessage > 0 {
		return o.MaxPerMessage
	}
	return DefaultMaxPerMessage
}

// dedupe suppresses repeats of the same finding within a window.
//
// Keyed by the finding rather than the event: two denials of the same path by
// two pids of one crash-looping container are the same finding, and treating
// them as different is how a notifier becomes noise.
type dedupe struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time
	// now is injectable so the window is testable without sleeping.
	now func() time.Time
}

func newDedupe(window time.Duration) *dedupe {
	if window == 0 {
		window = DefaultDedupeWindow
	}
	return &dedupe{window: window, seen: make(map[string]time.Time), now: time.Now}
}

// allow reports whether a finding should be delivered, and records it.
func (d *dedupe) allow(key string) bool {
	if d.window < 0 {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	if last, ok := d.seen[key]; ok && now.Sub(last) < d.window {
		return false
	}
	d.seen[key] = now

	// Evict under the lock already held. Without this the map grows with every
	// distinct finding for the life of the agent, and a node under attack
	// produces a great many distinct findings.
	if len(d.seen) > 4096 {
		for k, t := range d.seen {
			if now.Sub(t) >= d.window {
				delete(d.seen, k)
			}
		}
	}
	return true
}

// FindingKey identifies a finding for deduplication.
//
// Deliberately excludes the pid and the timestamp: those are exactly what make
// two occurrences of one problem look different. It keys on the workload
// rather than the pod, because a Deployment rolling out produces a new pod name
// per replica and one message per replica for one misconfiguration is the noise
// this exists to stop.
func FindingKey(ev *Event) string {
	if ev == nil {
		return ""
	}
	var b strings.Builder
	if k := ev.Kubernetes; k != nil {
		b.WriteString(k.Namespace)
		b.WriteByte('/')
		if k.WorkloadName != "" {
			b.WriteString(k.WorkloadKind)
			b.WriteByte('/')
			b.WriteString(k.WorkloadName)
		} else {
			b.WriteString(k.Pod)
		}
	} else {
		fmt.Fprintf(&b, "cgroup:%d", ev.CgroupID)
	}
	b.WriteByte('|')
	b.WriteString(string(ev.Type))
	b.WriteByte('|')
	b.WriteString(string(ev.Action))
	b.WriteByte('|')
	b.WriteString(FindingSubject(ev))
	return b.String()
}

// FindingSubject is what the finding is about: the path, the destination, the
// binary, the capability.
func FindingSubject(ev *Event) string {
	if ev == nil {
		return ""
	}
	switch {
	case ev.File != nil:
		return ev.File.Path
	case ev.Network != nil:
		if n := ev.Network.DestinationName; n != "" {
			return fmt.Sprintf("%s:%d", n, ev.Network.DestinationPort)
		}
		return fmt.Sprintf("%s:%d", ev.Network.DestinationIP, ev.Network.DestinationPort)
	case ev.Exec != nil:
		return ev.Exec.Binary
	case ev.Capability != nil:
		return ev.Capability.Name
	case ev.Syscall != nil:
		return ev.Syscall.Name
	}
	return ""
}

// WorkloadOf names the workload an event belongs to, for a message heading.
func WorkloadOf(ev *Event) string {
	if ev == nil {
		return ""
	}
	k := ev.Kubernetes
	if k == nil {
		return fmt.Sprintf("cgroup %d", ev.CgroupID)
	}
	switch {
	case k.WorkloadKind != "" && k.WorkloadName != "":
		return fmt.Sprintf("%s/%s in %s", k.WorkloadKind, k.WorkloadName, k.Namespace)
	case k.Pod != "":
		return fmt.Sprintf("%s/%s", k.Namespace, k.Pod)
	}
	return fmt.Sprintf("cgroup %d", ev.CgroupID)
}

// selectFindings filters a batch to what is worth delivering, oldest first so
// a message reads in the order things happened.
func selectFindings(events []*Event, all bool, d *dedupe) []*Event {
	out := make([]*Event, 0, len(events))
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if !all && !ev.Denied() {
			continue
		}
		if d != nil && !d.allow(FindingKey(ev)) {
			continue
		}
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp.Time().Before(out[j].Timestamp.Time())
	})
	return out
}

func batchSummary(findings []*Event, denied int, source string) string {
	var s string
	if denied > 0 {
		s = fmt.Sprintf("Pahlevan denied %d operation%s", denied, plural(denied))
	} else {
		s = fmt.Sprintf("Pahlevan observed %d operation%s", len(findings), plural(len(findings)))
	}
	if source != "" {
		s += " on " + source
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Truncate cuts a string to n characters and marks it, so a reader can tell a
// short value from the front of a long one.
func Truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// postJSON sends one JSON body and returns an error describing a non-2xx.
func postJSON(ctx context.Context, c *http.Client, url string, body any, headers map[string]string) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding the notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return checkStatus(url, resp)
}

// checkStatus turns a non-2xx into an error carrying the body.
//
// The body of a rejected notification usually says exactly what is wrong - an
// expired Slack webhook, a bad PagerDuty routing key - and discarding it leaves
// an operator with a bare status code.
func checkStatus(url string, resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	snippet := make([]byte, 256)
	n, _ := resp.Body.Read(snippet)
	return fmt.Errorf("%s returned %s: %s", url, resp.Status, strings.TrimSpace(string(snippet[:n])))
}

// SlackNotifier posts denials to a Slack incoming webhook.
type SlackNotifier struct {
	opts   NotifyOptions
	client *http.Client
	dedupe *dedupe
	mu     sync.Mutex
	closed bool
}

// NewSlackNotifier builds a Slack sink from an incoming-webhook URL.
func NewSlackNotifier(opts NotifyOptions) (*SlackNotifier, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("a Slack notifier needs an incoming-webhook URL")
	}
	return &SlackNotifier{
		opts: opts, client: opts.httpClient(), dedupe: newDedupe(opts.DedupeWindow),
	}, nil
}

func (s *SlackNotifier) Name() string { return "slack" }

func (s *SlackNotifier) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackBlock struct {
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
}

type slackPayload struct {
	// Text is the notification preview and the fallback for clients that do
	// not render blocks. Omitting it produces a push notification saying only
	// "attachment", which is useless on a phone at 3am.
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks,omitempty"`
}

// Export posts one message describing the batch.
func (s *SlackNotifier) Export(ctx context.Context, events []*Event) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	findings := selectFindings(events, s.opts.AllEvents, s.dedupe)
	if len(findings) == 0 {
		return nil
	}
	return postJSON(ctx, s.client, s.opts.URL, s.payload(findings), nil)
}

func (s *SlackNotifier) payload(findings []*Event) slackPayload {
	shown := findings
	if limit := s.opts.maxPerMessage(); len(shown) > limit {
		shown = shown[:limit]
	}
	denied := 0
	for _, ev := range findings {
		if ev.Denied() {
			denied++
		}
	}
	heading := batchSummary(findings, denied, s.opts.Source)

	blocks := []slackBlock{{Type: "header", Text: &slackText{Type: "plain_text", Text: heading}}}
	for _, ev := range shown {
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: slackLine(ev)},
		})
	}
	if len(findings) > len(shown) {
		blocks = append(blocks, slackBlock{
			Type: "context",
			Elements: []slackText{{
				Type: "mrkdwn",
				Text: fmt.Sprintf("_and %d more in this batch_", len(findings)-len(shown)),
			}},
		})
	}
	return slackPayload{Text: heading, Blocks: blocks}
}

// slackLine renders one finding, workload bold because that is what a reader
// scans for.
func slackLine(ev *Event) string {
	line := fmt.Sprintf("*%s*\n%s", WorkloadOf(ev), SummaryLine(ev))
	if ev.Exec != nil && ev.Exec.CommandLine != "" {
		// The command line is the difference between "python3 was denied" and
		// knowing what it was asked to run.
		line += "\n`" + Truncate(ev.Exec.CommandLine, 300) + "`"
	}
	return line
}

// PagerDutyNotifier raises incidents through the Events API v2.
type PagerDutyNotifier struct {
	opts       NotifyOptions
	routingKey string
	severity   string
	client     *http.Client
	dedupe     *dedupe
	mu         sync.Mutex
	closed     bool
}

// PagerDutyOptions configures the PagerDuty sink.
type PagerDutyOptions struct {
	NotifyOptions
	// RoutingKey is the integration key of the service to alert. Required.
	RoutingKey string
	// Severity is critical, error, warning or info. Empty means error.
	Severity string
}

// NewPagerDutyNotifier builds a PagerDuty sink.
func NewPagerDutyNotifier(opts PagerDutyOptions) (*PagerDutyNotifier, error) {
	if opts.RoutingKey == "" {
		return nil, fmt.Errorf("a PagerDuty notifier needs a routing key")
	}
	if opts.URL == "" {
		opts.URL = DefaultPagerDutyURL
	}
	sev := strings.ToLower(strings.TrimSpace(opts.Severity))
	switch sev {
	case "":
		sev = "error"
	case "critical", "error", "warning", "info":
	default:
		return nil, fmt.Errorf(
			"PagerDuty severity %q is not one of critical, error, warning, info", opts.Severity)
	}
	return &PagerDutyNotifier{
		opts: opts.NotifyOptions, routingKey: opts.RoutingKey, severity: sev,
		client: opts.NotifyOptions.httpClient(), dedupe: newDedupe(opts.DedupeWindow),
	}, nil
}

func (p *PagerDutyNotifier) Name() string { return "pagerduty" }

func (p *PagerDutyNotifier) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

type pagerDutyDetail struct {
	Summary       string         `json:"summary"`
	Source        string         `json:"source"`
	Severity      string         `json:"severity"`
	Timestamp     string         `json:"timestamp,omitempty"`
	Component     string         `json:"component,omitempty"`
	Group         string         `json:"group,omitempty"`
	Class         string         `json:"class,omitempty"`
	CustomDetails map[string]any `json:"custom_details,omitempty"`
}

type pagerDutyEvent struct {
	RoutingKey  string          `json:"routing_key"`
	EventAction string          `json:"event_action"`
	DedupKey    string          `json:"dedup_key,omitempty"`
	Payload     pagerDutyDetail `json:"payload"`
}

// Export raises one incident per distinct finding.
//
// Not one per batch: PagerDuty's model is an incident per problem, and folding
// four unrelated denials into one incident means resolving it resolves all
// four. The dedup key is the finding, so the same problem re-triggers the same
// incident rather than opening another.
func (p *PagerDutyNotifier) Export(ctx context.Context, events []*Event) error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return ErrClosed
	}

	var errs []string
	for _, ev := range selectFindings(events, p.opts.AllEvents, p.dedupe) {
		body := pagerDutyEvent{
			RoutingKey:  p.routingKey,
			EventAction: "trigger",
			DedupKey:    FindingKey(ev),
			Payload: pagerDutyDetail{
				Summary:   Truncate(SummaryLine(ev), 1024),
				Source:    p.source(ev),
				Severity:  p.severity,
				Timestamp: ev.Timestamp.Time().UTC().Format(time.RFC3339),
				Component: string(ev.Type),
				Group:     WorkloadOf(ev),
				Class:     string(ev.Action),
				CustomDetails: map[string]any{
					"process":  ev.Process.Comm,
					"pid":      ev.Process.PID,
					"subject":  FindingSubject(ev),
					"cgroupId": ev.CgroupID,
					"node":     p.opts.Source,
				},
			},
		}
		if err := postJSON(ctx, p.client, p.opts.URL, body, nil); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("pagerduty: %s", strings.Join(errs, "; "))
	}
	return nil
}

// source is PagerDuty's "where did this come from": the workload, not the node.
// Somebody paged at 3am needs to know which service is affected; the node is in
// the details.
func (p *PagerDutyNotifier) source(ev *Event) string {
	if s := WorkloadOf(ev); s != "" {
		return s
	}
	if p.opts.Source != "" {
		return p.opts.Source
	}
	return "pahlevan"
}

// TemplateNotifier POSTs a body rendered from a Go text/template.
//
// The escape hatch for every destination that is not Slack or PagerDuty:
// Microsoft Teams, Discord, Opsgenie, an internal ticket API. Rather than a
// sink per destination, the operator writes the body their destination expects.
type TemplateNotifier struct {
	opts        NotifyOptions
	tmpl        *template.Template
	contentType string
	headers     map[string]string
	client      *http.Client
	dedupe      *dedupe
	mu          sync.Mutex
	closed      bool
}

// TemplateOptions configures the templated sink.
type TemplateOptions struct {
	NotifyOptions
	// Template is a Go text/template rendered with a TemplateData value.
	Template string
	// ContentType defaults to application/json.
	ContentType string
	// Headers are added to every request, for an API key or tenant id.
	Headers map[string]string
}

// TemplateData is what a notification template is rendered with.
type TemplateData struct {
	// Source is the sending agent, normally the node name.
	Source string
	// Events are the findings in this delivery, oldest first.
	Events []*Event
	// Denied is how many were refused in-kernel.
	Denied int
	// Summary is a one-line description of the batch.
	Summary string
}

// TemplateFuncs are the helpers a notification template can call, so an author
// does not have to reimplement them in template syntax.
func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		// summary renders one event the way every other Pahlevan surface does,
		// so a Teams card and a Loki line say the same words.
		"summary":  SummaryLine,
		"workload": WorkloadOf,
		"subject":  FindingSubject,
		// json quotes a value for embedding in a JSON template, which almost
		// every destination wants and which a naive template gets wrong the
		// first time a path contains a quote.
		"json": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
		"truncate": Truncate,
		"upper":    strings.ToUpper,
		"lower":    strings.ToLower,
		"join":     strings.Join,
	}
}

// NewTemplateNotifier builds a templated sink.
//
// The template is parsed here rather than at the first delivery, so a syntax
// error is a startup failure naming the mistake instead of an error logged once
// per batch while notifications silently never arrive.
func NewTemplateNotifier(opts TemplateOptions) (*TemplateNotifier, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("a templated notifier needs a URL")
	}
	if strings.TrimSpace(opts.Template) == "" {
		return nil, fmt.Errorf("a templated notifier needs a template")
	}
	tmpl, err := template.New("notify").Funcs(TemplateFuncs()).Parse(opts.Template)
	if err != nil {
		return nil, fmt.Errorf("parsing the notification template: %w", err)
	}
	ct := opts.ContentType
	if ct == "" {
		ct = "application/json"
	}
	return &TemplateNotifier{
		opts: opts.NotifyOptions, tmpl: tmpl, contentType: ct, headers: opts.Headers,
		client: opts.NotifyOptions.httpClient(), dedupe: newDedupe(opts.DedupeWindow),
	}, nil
}

func (t *TemplateNotifier) Name() string { return "template" }

func (t *TemplateNotifier) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

// Export renders one body for the batch and POSTs it.
func (t *TemplateNotifier) Export(ctx context.Context, events []*Event) error {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return ErrClosed
	}

	findings := selectFindings(events, t.opts.AllEvents, t.dedupe)
	if len(findings) == 0 {
		return nil
	}
	if limit := t.opts.maxPerMessage(); len(findings) > limit {
		findings = findings[:limit]
	}
	denied := 0
	for _, ev := range findings {
		if ev.Denied() {
			denied++
		}
	}

	var buf bytes.Buffer
	if err := t.tmpl.Execute(&buf, TemplateData{
		Source:  t.opts.Source,
		Events:  findings,
		Denied:  denied,
		Summary: batchSummary(findings, denied, t.opts.Source),
	}); err != nil {
		return fmt.Errorf("rendering the notification template: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.opts.URL, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("Content-Type", t.contentType)
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return checkStatus(t.opts.URL, resp)
}
