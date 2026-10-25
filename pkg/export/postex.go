// Post-exploitation shapes recognised from the structure of an event.
//
// Everything else in this package reports what the kernel saw and leaves the
// judgement to the allow-set: an operation outside the learned baseline is
// denied, an operation inside it is not, and the envelope says which. That is
// the right default and it is what makes Pahlevan workload-agnostic.
//
// It is also not enough on its own for two shapes, because both of them can
// sit *inside* a learned baseline and still be an intrusion:
//
//   - A request-serving process execs a shell or an interpreter. This is what
//     a web shell looks like from the kernel: php-fpm -> sh, httpd -> bash,
//     java -> sh. The exec itself is ordinary, and an image whose entrypoint
//     is a shell wrapper teaches the baseline that sh is normal, after which
//     the generic deny has nothing to say. The parent is the whole signal.
//
//   - A server-side script is written into a directory the web server serves.
//     A .php under /var/www or a .jsp under webapps/ is a file write like any
//     other, and a workload that writes to its own document root during
//     learning, as a cache or an upload directory, grants that write for good.
//     The extension and the directory together are the signal.
//
// pkg/export already carried ParentComm and AncestryChain for display, so both
// shapes were representable and neither was keyed on. This file keys on them.
//
// What this is not: a vulnerability detector. A signal here says a process did
// something whose shape matches post-exploitation, nothing about how the
// attacker got in. The initial remote code execution in the PHP2Shell pair
// (CVE-2026-109618 and CVE-2026-109619) happens inside the php-fpm worker and
// produces no exec, no open and no connect, so it is not observable here at
// all; see docs/cve-coverage.md for what is and is not seen, hook by hook.
//
// What this is not, second: enforcement. Both signals are computed on the
// export path, after the kernel has already allowed or denied the operation,
// so a signal never blocks anything. It decides whether the event is an alert.

package export

import (
	"path"
	"strings"
)

// Signal names a post-exploitation shape recognised from an event's structure
// rather than from a deviation from the learned baseline.
//
// The distinction matters when reading a report: a denial means the operation
// was outside the allow-set, which is a statement about this workload. A
// signal means the operation had a shape that is hostile regardless of what
// the workload learned.
type Signal string

const (
	// SignalServerSpawnedShell is a shell or interpreter exec with a
	// request-serving process in its ancestry: the kernel-visible shape of a
	// web shell, a command-injection payload or an exploited server running
	// its first command.
	SignalServerSpawnedShell Signal = "server-spawned-shell"

	// SignalWebShellWrite is a write to a server-side script in a directory a
	// web server serves: a .php dropped into a document root, a .jsp dropped
	// into webapps/. The shape of a web shell being planted rather than run.
	SignalWebShellWrite Signal = "web-shell-write"
)

// Signalled reports whether the event carries any post-exploitation signal.
//
// Read by the notifiers and by Filter: a signalled event is worth delivering
// even when the kernel allowed it, which is every event on a kernel without
// the BPF LSM, where nothing can be denied at all.
func (e *Event) Signalled() bool { return e != nil && len(e.Signals) > 0 }

// HasSignal reports whether the event carries one particular signal.
func (e *Event) HasSignal(s Signal) bool {
	if e == nil {
		return false
	}
	for _, got := range e.Signals {
		if got == s {
			return true
		}
	}
	return false
}

// SignalNames renders the signals as a comma separated list for a log line or
// a message body. Empty for an event carrying none.
func (e *Event) SignalNames() string {
	if e == nil || len(e.Signals) == 0 {
		return ""
	}
	names := make([]string, 0, len(e.Signals))
	for _, s := range e.Signals {
		names = append(names, string(s))
	}
	return strings.Join(names, ",")
}

// Annotate fills in Event.Signals and counts what it found.
//
// Called on the export path before the filter runs, because the filter's
// decision depends on the answer: an event that is a signal must survive
// DenialsOnly whether or not the kernel denied it.
func Annotate(ev *Event) {
	if ev == nil {
		return
	}
	ev.Signals = DetectSignals(ev)
	for _, s := range ev.Signals {
		countSignal(s)
	}
}

// DetectSignals returns the post-exploitation signals an event's structure
// matches, in a stable order. It allocates nothing for the overwhelming
// majority of events, which match none.
func DetectSignals(ev *Event) []Signal {
	if ev == nil {
		return nil
	}
	var out []Signal
	if serverSpawnedShell(ev) {
		out = append(out, SignalServerSpawnedShell)
	}
	if webShellWrite(ev) {
		out = append(out, SignalWebShellWrite)
	}
	return out
}

// serverSpawnedShell reports the web shell exec shape: this exec is a shell or
// an interpreter, and a request-serving process is one of its ancestors.
//
// Ancestry rather than the immediate parent alone, because the second command
// an attacker runs is a grandchild: php-fpm -> sh -> curl is the same
// intrusion as php-fpm -> sh, and a rule that only looked at ParentComm would
// report the first and miss the rest.
func serverSpawnedShell(ev *Event) bool {
	if ev.Exec == nil || ev.Exec.Exited {
		return false
	}
	child := execComm(ev)
	if !shellLike(child) {
		return false
	}
	// A server re-execing itself is a reload, not an intrusion, and a server
	// whose own name is interpreter-like (node) would otherwise report every
	// worker it forks.
	for _, name := range ancestorComms(ev) {
		if name == child {
			continue
		}
		if serverRuntime(name) {
			return true
		}
	}
	return false
}

// webShellWrite reports the web shell drop shape: a write to a server-side
// script under a directory a web server serves.
//
// Both halves are required. A .php written to /tmp is a staging step, not a
// planted shell, and a .png written to a document root is an upload. Only the
// combination is the thing that is remotely reachable the moment it lands.
func webShellWrite(ev *Event) bool {
	if ev.File == nil || ev.File.Flags&writeFlagBit == 0 {
		return false
	}
	p := ev.File.Path
	if p == "" {
		return false
	}
	return servableDir(p) && serverSideScript(p)
}

// execComm names the process that execed, preferring the comm the kernel
// reported and falling back to the binary's base name.
//
// The fallback matters at exactly the moment the signal does: comm is the
// *old* name until the exec completes, so an event captured in
// bprm_check_security can still carry the parent's comm while Binary already
// names the shell.
func execComm(ev *Event) string {
	if ev.Exec != nil && ev.Exec.Binary != "" {
		if base := path.Base(ev.Exec.Binary); base != "" && base != "." && base != "/" {
			return base
		}
	}
	return ev.Process.Comm
}

// ancestorComms lists the event's ancestors nearest first.
//
// Three sources, because an envelope may have come from any of them: the
// structured ancestry the exec hook captured, the rendered chain that survives
// a round trip through JSON or gRPC, and ParentComm, which every event type
// carries even when there is no exec record at all.
func ancestorComms(ev *Event) []string {
	var out []string
	if ev.Exec != nil {
		for _, a := range ev.Exec.Ancestry {
			if a.Comm != "" {
				out = append(out, a.Comm)
			}
		}
		if len(out) == 0 && ev.Exec.AncestryChain != "" {
			// The chain renders oldest first; reverse it so both sources agree
			// on "nearest first" and a caller can stop at the first match.
			parts := strings.Split(ev.Exec.AncestryChain, " -> ")
			for i := len(parts) - 1; i >= 0; i-- {
				if name := strings.TrimSpace(parts[i]); name != "" {
					out = append(out, name)
				}
			}
		}
	}
	if ev.Process.ParentComm != "" {
		out = append(out, ev.Process.ParentComm)
	}
	return out
}

// serverComms are the comms of processes whose job is to answer requests from
// the network. A shell with one of these above it is the web shell shape.
//
// Exact names only; the prefix cases are below.
var serverComms = map[string]bool{
	"nginx":     true,
	"httpd":     true,
	"apache2":   true,
	"lighttpd":  true,
	"caddy":     true,
	"openresty": true,
	"tomcat":    true,
	"jetty":     true,
	"java":      true,
	"node":      true,
	"gunicorn":  true,
	"uwsgi":     true,
	"puma":      true,
	"unicorn":   true,
	"passenger": true,
	"hypercorn": true,
	"daphne":    true,
	"thin":      true,

	// Plex Media Server, as the kernel reports it. comm is capped at 15
	// characters plus the terminator, so the name arrives truncated and an
	// exact match on the full name would never fire. The Plex2Shell chain
	// (CVE-2026-96652, -96654, -96655, -96656) ends in this process running
	// commands, so the truncated form is the one worth matching.
	"Plex Media Serv": true,
}

// serverCommPrefixes catch the runtimes that rename themselves at startup.
//
// php-fpm is the reason this list exists: a worker sets its process title to
// "php-fpm: pool www", and depending on the build and on prctl(PR_SET_NAME)
// that is what comm reports, truncated. An exact match on "php-fpm" misses
// every worker, which is to say it misses the only process that matters.
var serverCommPrefixes = []string{
	"php-fpm",
	"php-cgi",
	"frankenphp",
	"nginx:",
	"httpd:",
	"apache2:",
	"gunicorn:",
}

// serverRuntime reports whether a comm names a request-serving process.
func serverRuntime(comm string) bool {
	if comm == "" {
		return false
	}
	if serverComms[comm] {
		return true
	}
	for _, p := range serverCommPrefixes {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

// shellComms are the shells. A server process execing one of these is doing
// something no request handler needs to do.
var shellComms = map[string]bool{
	"sh":      true,
	"bash":    true,
	"dash":    true,
	"ash":     true,
	"zsh":     true,
	"ksh":     true,
	"csh":     true,
	"tcsh":    true,
	"fish":    true,
	"busybox": true,
}

// interpreterComms are the scripting interpreters. Separate from the shells
// only to keep the two lists readable; a signal does not distinguish them,
// because `php-fpm -> perl` and `php-fpm -> sh` are the same finding.
//
// node is deliberately absent: it is in serverComms, and a Node server forking
// workers would otherwise report itself on every one.
var interpreterComms = map[string]bool{
	"python":  true,
	"python2": true,
	"python3": true,
	"perl":    true,
	"ruby":    true,
	"lua":     true,
	"tclsh":   true,
	"php":     true,
	"awk":     true,
	"gawk":    true,
}

// shellLike reports whether a comm names a shell or a scripting interpreter.
func shellLike(comm string) bool {
	if comm == "" {
		return false
	}
	return shellComms[comm] || interpreterComms[comm]
}

// servableDirs are path fragments that mean "a web server serves this".
//
// Fragments rather than prefixes, because the interesting ones are relative to
// an install that moves: Tomcat's webapps/ is under /opt, /usr/local or
// /var/lib depending on the packaging, and PTC Windchill's login directory,
// where CVE-2026-12569 drops its JSP shells, is under whichever root the
// deployment chose.
var servableDirs = []string{
	"/var/www/",
	"/usr/share/nginx/html/",
	"/usr/local/apache2/htdocs/",
	"/srv/http/",
	"/srv/www/",
	"/htdocs/",
	"/public_html/",
	"/wwwroot/",
	"/webapps/",
	"/windchill/login/",
	"/www/html/",
}

// servableDir reports whether a path lies under a directory a web server
// serves. Matched case-insensitively: Windchill's path is mixed case, and a
// case-sensitive match on a case-insensitive deployment is a silent miss.
func servableDir(p string) bool {
	lower := strings.ToLower(p)
	for _, d := range servableDirs {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// scriptExtensions are the extensions a web server hands to an interpreter
// instead of returning as bytes. One of these in a document root is reachable
// code the moment the file exists.
var scriptExtensions = map[string]bool{
	".php":    true,
	".php3":   true,
	".php4":   true,
	".php5":   true,
	".php7":   true,
	".php8":   true,
	".phps":   true,
	".phtml":  true,
	".phar":   true,
	".jsp":    true,
	".jspx":   true,
	".jspf":   true,
	".jsw":    true,
	".jsv":    true,
	".asp":    true,
	".aspx":   true,
	".ashx":   true,
	".asmx":   true,
	".cfm":    true,
	".cfml":   true,
	".cgi":    true,
	".pl":     true,
	".phtm":   true,
	".shtml":  true,
}

// serverSideScript reports whether a path names a file a web server would
// execute rather than serve.
//
// The extension is taken after stripping one trailing upload suffix, because
// the classic bypass is to land the file as shell.php.bak or shell.jsp.tmp and
// rename it afterwards: the write is the event worth reporting, and it happens
// under the suffixed name.
func serverSideScript(p string) bool {
	lower := strings.ToLower(path.Base(p))
	if ext := path.Ext(lower); scriptExtensions[ext] {
		return true
	}
	trimmed := strings.TrimSuffix(lower, path.Ext(lower))
	if trimmed == "" || trimmed == lower {
		return false
	}
	return scriptExtensions[path.Ext(trimmed)]
}
