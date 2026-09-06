// Package vm holds the guard for the kernel-test workflow.
//
// hack/vm/ boots a VM with lsm=bpf so eBPF programs are loaded by a real
// kernel. .github/workflows/vm-tests.yml runs that on a pull request, but only
// one that touches a path in its filter list. A filter list is a promise that
// nothing a kernel can reject lives outside it, and nothing was checking the
// promise: adding bpf/net/parser.c, or a second object directory, would fall
// outside 'bpf/**' the moment somebody nested it differently, and the job
// would go on reporting success by never running.
//
// So this walks the tree, finds every file whose contents a kernel decides
// about, and asserts the workflow would run for a change to it.
package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// repoRoot is two levels up from hack/vm.
const repoRoot = "../.."

const workflowPath = repoRoot + "/.github/workflows/vm-tests.yml"

// workflow is the subset of the workflow file this test reads. Decoding into a
// typed struct rather than map[string]any means a restructure that moves the
// filters somewhere else fails here instead of silently matching nothing.
//
// The trigger block is tagged "true", not "on". `on` is one of YAML 1.1's
// boolean spellings, so an unquoted `on:` key parses as the boolean true and
// arrives here under that name. GitHub reads the same file as a workflow
// trigger; this is a quirk of parsing it as plain YAML, not a mistake in the
// workflow.
type workflow struct {
	On struct {
		Push struct {
			Paths []string `json:"paths"`
		} `json:"push"`
		PullRequest struct {
			Paths []string `json:"paths"`
		} `json:"pull_request"`
		Schedule []struct {
			Cron string `json:"cron"`
		} `json:"schedule"`
	} `json:"true"`
	Jobs map[string]struct {
		RunsOn         string `json:"runs-on"`
		TimeoutMinutes int    `json:"timeout-minutes"`
		Steps          []struct {
			Name string `json:"name"`
			Run  string `json:"run"`
			Uses string `json:"uses"`
		} `json:"steps"`
	} `json:"jobs"`
}

func loadWorkflow(t *testing.T) *workflow {
	t.Helper()
	b, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("reading the kernel-test workflow: %v", err)
	}
	var w workflow
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatalf("parsing %s: %v", workflowPath, err)
	}
	return &w
}

// matchesGlob reports whether a repo-relative path is selected by one GitHub
// Actions path filter.
//
// The filter syntax is not filepath.Match: "**" crosses separators and "*"
// does not, which is the whole distinction the filters rely on. Implemented
// directly rather than pulled in, because the alternative is a dependency that
// has to be trusted to agree with GitHub about the one case that matters.
func matchesGlob(pattern, path string) bool {
	// A bare directory prefix is the common form and worth short-circuiting.
	if strings.HasSuffix(pattern, "/**") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "**"))
	}
	if pattern == path {
		return true
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchSegments(pat, seg []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// Zero or more segments: try every split point. The pattern list
			// shrinks on each recursion, so this terminates.
			for i := 0; i <= len(seg); i++ {
				if matchSegments(pat[1:], seg[i:]) {
					return true
				}
			}
			return false
		}
		if len(seg) == 0 {
			return false
		}
		ok, err := filepath.Match(pat[0], seg[0])
		if err != nil || !ok {
			return false
		}
		pat, seg = pat[1:], seg[1:]
	}
	return len(seg) == 0
}

// kernelDecidedFiles lists every tracked file whose contents a kernel would
// accept or reject: the BPF C sources and headers, the compiled objects, the
// Go that loads and attaches them, and the harness that boots the guest.
//
// The walk is deliberately over the real tree rather than a hardcoded list.
// A hardcoded list is the thing that goes stale, and going stale is the
// failure this test exists to catch.
func kernelDecidedFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	roots := []string{"bpf", "pkg/ebpf", "hack/vm"}
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join(repoRoot, root), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			switch filepath.Ext(p) {
			case ".c", ".h", ".o", ".go", ".sh":
			default:
				return nil
			}
			// vmlinux.h is generated and gitignored; it is not a file a change
			// can arrive in.
			if filepath.Base(p) == "vmlinux.h" {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no eBPF sources at all; the walk roots are wrong and this test is proving nothing")
	}
	return out
}

func TestEveryKernelDecidedFileTriggersTheWorkflow(t *testing.T) {
	w := loadWorkflow(t)

	for _, tc := range []struct {
		trigger string
		paths   []string
	}{
		{"push", w.On.Push.Paths},
		{"pull_request", w.On.PullRequest.Paths},
	} {
		if len(tc.paths) == 0 {
			t.Fatalf("the %s trigger has no path filter; either it runs on everything or it was renamed", tc.trigger)
		}
		for _, f := range kernelDecidedFiles(t) {
			matched := false
			for _, pat := range tc.paths {
				if matchesGlob(pat, f) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("a change to %s would not run the kernel tests on %s; add a filter covering it to %s",
					f, tc.trigger, workflowPath)
			}
		}
	}
}

func TestTheWorkflowActuallyRunsTheKernelTests(t *testing.T) {
	w := loadWorkflow(t)
	job, ok := w.Jobs["kernel"]
	if !ok {
		t.Fatalf("no 'kernel' job in %s; the jobs present are %v", workflowPath, keysOf(w.Jobs))
	}

	// A workflow that boots the VM and never runs anything in it is the exact
	// shape of a green check that proves nothing.
	var ranTests, bootedVM bool
	for _, s := range job.Steps {
		if strings.Contains(s.Run, "make vm-test") {
			ranTests = true
		}
		if strings.Contains(s.Run, "hack/vm/up.sh") {
			bootedVM = true
		}
	}
	if !bootedVM {
		t.Error("no step boots the VM")
	}
	if !ranTests {
		t.Error("no step runs `make vm-test`, so the job would report success without loading a program")
	}

	// Emulation would take long enough that the job would be disabled rather
	// than fixed, so the runner has to be one with KVM and the timeout has to
	// allow a full provision.
	if !strings.HasPrefix(job.RunsOn, "ubuntu-") {
		t.Errorf("runs-on is %q; the harness needs a Linux runner with /dev/kvm", job.RunsOn)
	}
	if job.TimeoutMinutes < 30 {
		t.Errorf("timeout-minutes is %d; provisioning the guest alone takes longer than that on a cold cache", job.TimeoutMinutes)
	}
}

func TestTheWorkflowRunsOnASchedule(t *testing.T) {
	// Path filters mean a kernel update in the cloud image, or a change
	// somewhere else that breaks a program, is invisible until the next
	// pull request that happens to touch bpf/. The schedule is what makes
	// that a bounded wait.
	w := loadWorkflow(t)
	if len(w.On.Schedule) == 0 {
		t.Error("no schedule; a break that arrives from outside the filtered paths would go unnoticed")
	}
	for _, s := range w.On.Schedule {
		if strings.TrimSpace(s.Cron) == "" {
			t.Error("a schedule entry has an empty cron expression")
		}
	}
}

func TestMatchesGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"bpf/**", "bpf/enforce.h", true},
		{"bpf/**", "bpf/net/parser.c", true},
		{"bpf/**", "bpfother/x.c", false},
		{"bpf/**", "pkg/ebpf/manager.go", false},
		{"pkg/ebpf/**", "pkg/ebpf/manager.go", true},
		{"Makefile", "Makefile", true},
		{"Makefile", "hack/Makefile", false},
		// "*" must not cross a separator, which is the difference the filters
		// depend on.
		{"bpf/*.c", "bpf/enforce.c", true},
		{"bpf/*.c", "bpf/net/enforce.c", false},
		{"**/*.c", "bpf/net/enforce.c", true},
		{"**/*.c", "enforce.c", true},
		{"**", "anything/at/all", true},
	}
	for _, c := range cases {
		if got := matchesGlob(c.pattern, c.path); got != c.want {
			t.Errorf("matchesGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func BenchmarkMatchesGlob(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchesGlob("pkg/ebpf/**", "pkg/ebpf/manager.go")
	}
}

func BenchmarkMatchesGlobDoubleStar(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchesGlob("**/*.c", "bpf/net/enforce.c")
	}
}

// The Makefile and env.sh both decide where the harness keeps its artifacts,
// and they have to agree. Hardcoding .vmcache in the vm-test recipe worked for
// as long as nobody set the variable, and broke the first time CI put the
// cache on the runner's scratch disk:
//
//	fatal: could not open '.vmcache/src.tar' for writing: No such file or directory
//
// The VM had booted, the bpf LSM was active, and not one program was loaded.
// Asserted through `make -n` rather than by grepping the Makefile for a
// string, so it tests the recipe make actually expands.
func TestVMTestHonoursTheCacheLocation(t *testing.T) {
	const elsewhere = "/tmp/pahlevan-vm-cache-probe"

	out, err := exec.Command("make", "-n", "-C", repoRoot, "vm-test").CombinedOutput()
	if err != nil {
		t.Fatalf("make -n vm-test: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), ".vmcache/src.tar") {
		t.Errorf("the default recipe does not use .vmcache; it reads:\n%s", out)
	}

	cmd := exec.Command("make", "-n", "-C", repoRoot, "vm-test")
	cmd.Env = append(os.Environ(), "PAHLEVAN_VM_CACHE="+elsewhere)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n vm-test with PAHLEVAN_VM_CACHE: %v\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, elsewhere+"/src.tar") {
		t.Errorf("PAHLEVAN_VM_CACHE=%s did not move the source tarball; the recipe reads:\n%s", elsewhere, got)
	}
	// The literal must be gone, not merely joined by another path that also
	// happens to be present.
	if strings.Contains(got, ".vmcache/") {
		t.Errorf("PAHLEVAN_VM_CACHE was set and the recipe still writes to .vmcache/:\n%s", got)
	}
}
