package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/obsernetics/pahlevan/cmd/pahlevan/commands"
	"github.com/obsernetics/pahlevan/pkg/coverage"
)

// Documentation goes stale silently. Code that is wrong fails to build or
// fails a test; prose that is wrong keeps rendering, so the only signal is a
// reader who believes it and is misled.
//
// Three things had already drifted before these existed. A program shipped and
// the README went on listing the set from before it. `pahlevan ui` landed and
// no file in the repo said the command existed, so the only way to find it was
// to run `pahlevan --help`. And the em dash rule, which is a house rule and not
// a preference, was enforced by review alone, which means it was enforced
// whenever somebody happened to look.
//
// Each test below derives what it expects from the tree rather than from a
// list written here, so adding a detector or a subcommand makes the test fail
// until it is documented. That is the point: the failure is the notification.

const (
	docsDir    = "../.."
	readmePath = "../../README.md"
)

// docFile is one documentation file with its contents.
type docFile struct {
	path string // repo-relative, for failure messages
	body string
}

// docCorpus is README.md plus every Markdown file under docs/, including
// subdirectories: docs/benchmarks/README.md is documentation a reader reaches
// from the README and rots the same way the top-level pages do.
func docCorpus(t *testing.T) []docFile {
	t.Helper()

	var out []docFile
	read := func(abs, rel string) {
		b, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		out = append(out, docFile{path: rel, body: string(b)})
	}

	read(readmePath, "README.md")

	root := filepath.Join(docsDir, "docs")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".md" {
			return nil
		}
		rel, relErr := filepath.Rel(docsDir, path)
		if relErr != nil {
			rel = path
		}
		read(path, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walking docs/: %v", err)
	}

	if len(out) < 2 {
		t.Fatal("found fewer than two documentation files; the paths are wrong and these tests are proving nothing")
	}
	return out
}

var whitespace = regexp.MustCompile(`\s+`)

// flatten collapses every run of whitespace to a single space. Markdown is
// hard-wrapped, so "pahlevan attack-surface" is routinely split across two
// lines; a test that searched the raw bytes would report a command as
// undocumented because of where the paragraph happened to wrap.
func flatten(s string) string {
	return whitespace.ReplaceAllString(s, " ")
}

// mentioned reports whether any document contains needle, ignoring wrapping,
// and names the file that did if one did.
func mentioned(corpus []docFile, needle string) (string, bool) {
	for _, d := range corpus {
		if strings.Contains(flatten(d.body), needle) {
			return d.path, true
		}
	}
	return "", false
}

// lineOf returns the 1-based line number of the first occurrence of needle in
// body, or 0 if it does not occur. Every failure below reports a line so the
// fix needs no second search.
func lineOf(body, needle string) int {
	i := strings.Index(body, needle)
	if i < 0 {
		return 0
	}
	return 1 + strings.Count(body[:i], "\n")
}

func TestEveryDetectorHookIsDocumented(t *testing.T) {
	// The failure this exists for: a program is added to bpf/ and registered
	// in pkg/coverage, and nothing outside the code says so. The hook string
	// is the one identifier that appears verbatim in both the table and the
	// prose, so it is what a reader greps for when a denial names it.
	corpus := docCorpus(t)
	for _, e := range coverage.Table {
		if _, ok := mentioned(corpus, e.Hook); !ok {
			t.Errorf("no documentation mentions %s (the %s detector), so Pahlevan watches something "+
				"it never tells anyone about.\n"+
				"Add it to the program table in README.md or to docs/architecture.md.",
				e.Hook, e.Detector)
		}
	}
}

// rootForDocs rebuilds the CLI's command tree the way cmd/pahlevan/main.go
// does. The constructors are called rather than main.go being parsed, so a
// renamed command is caught by the compiler and a command's real name comes
// from cobra rather than from a regexp's idea of one.
//
// It cannot import cmd/pahlevan itself: that is package main, and so is this.
// TestTheCommandListHereIsComplete guards the copy.
func rootForDocs() *cobra.Command {
	root := &cobra.Command{Use: "pahlevan"}
	root.AddCommand(
		commands.NewPolicyCommand(),
		commands.NewAttackSurfaceCommand(),
		commands.NewProfileCommand(),
		commands.NewNetpolCommand(),
		commands.NewStatusCommand(),
		commands.NewEventsCommand(),
		commands.NewLogsCommand(),
		commands.NewMetricsCommand(),
		commands.NewDebugCommand(),
		commands.NewCoverageCommand(),
		commands.NewUICommand(),
		commands.NewCompletionCommand(),
		commands.NewVersionCommand("dev", "unknown", "unknown"),
	)
	return root
}

func TestEverySubcommandIsDocumented(t *testing.T) {
	// `pahlevan ui` shipped and was documented nowhere. A command nobody has
	// written down is a command nobody runs, and --help is not documentation:
	// it is only reachable by somebody who already suspects the command is
	// there.
	corpus := docCorpus(t)
	for _, sub := range rootForDocs().Commands() {
		name := sub.Name()
		if sub.Hidden {
			continue // a hidden command is deliberately not offered to users
		}
		if _, ok := mentioned(corpus, "pahlevan "+name); !ok {
			t.Errorf("no documentation mentions `pahlevan %s`, so the command exists only for "+
				"whoever reads --help.\nAdd it to README.md or the relevant page under docs/.", name)
		}
	}
}

func TestTheCommandListHereIsComplete(t *testing.T) {
	// rootForDocs is a hand-copied list, and a stale one would make
	// TestEverySubcommandIsDocumented pass while a new command goes
	// undocumented - the test rotting in exactly the way it exists to prevent.
	// So count the constructors main.go actually registers and require the
	// same number here. This is the only place that reads main.go as text, and
	// it checks the test rather than deriving the names.
	b, err := os.ReadFile(filepath.Join(docsDir, "cmd", "pahlevan", "main.go"))
	if err != nil {
		t.Fatalf("reading cmd/pahlevan/main.go: %v", err)
	}
	src := string(b)

	// Scan the whole of NewRootCommand rather than the AddCommand argument
	// list. A command built into a variable first - which is what happened
	// when `ui` grew an Offline wrapper and a reference elsewhere in the
	// function - is still a registered command, and counting only the
	// argument list reported it missing.
	start := strings.Index(src, "func NewRootCommand()")
	if start < 0 {
		t.Fatal("cmd/pahlevan/main.go no longer defines NewRootCommand; this test cannot see the command list")
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatal("cannot find the end of NewRootCommand in cmd/pahlevan/main.go")
	}
	block := src[start : start+end]

	// Deduplicated: a constructor mentioned twice (assigned, then referenced)
	// is still one command.
	seen := map[string]bool{}
	var registered []string
	for _, m := range regexp.MustCompile(`commands\.New\w+Command\(`).FindAllString(block, -1) {
		if !seen[m] {
			seen[m] = true
			registered = append(registered, m)
		}
	}
	if len(registered) == 0 {
		t.Fatal("no command constructors found in NewRootCommand; the shape changed and this test is proving nothing")
	}

	if got, want := len(rootForDocs().Commands()), len(registered); got != want {
		t.Errorf("cmd/pahlevan/main.go registers %d commands but rootForDocs builds %d (line %d).\n"+
			"Add the new constructor to rootForDocs, or TestEverySubcommandIsDocumented will "+
			"never notice the command is undocumented.",
			want, got, lineOf(src, "func NewRootCommand()"))
	}
}

func TestNoDocumentationUsesAnEmDash(t *testing.T) {
	// A house rule, and one that review enforces only when somebody looks. The
	// separator is " - ". This catches the em dash that arrives by way of a
	// paste from an editor that substitutes one for "--".
	for _, d := range docCorpus(t) {
		for i, line := range strings.Split(d.body, "\n") {
			if strings.ContainsRune(line, '—') {
				t.Errorf("%s:%d contains an em dash; use \" - \" instead:\n\t%s",
					d.path, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// banned are strings that must never reach a published document: attribution
// for the tooling a commit happened to be written with, which says nothing
// about the software and everything about a workflow nobody reading the docs
// cares about.
var banned = []string{"Claude", "Anthropic", "Generated with", "\U0001F916"}

func TestNoDocumentationCarriesToolAttribution(t *testing.T) {
	// These arrive by paste, in a block appended to a message or a file, and
	// they survive review because they sit at the bottom where nobody is
	// reading. Matched case-insensitively: "generated with" and "Generated
	// With" are the same leak.
	for _, d := range docCorpus(t) {
		for i, line := range strings.Split(d.body, "\n") {
			lower := strings.ToLower(line)
			for _, bad := range banned {
				if strings.Contains(lower, strings.ToLower(bad)) {
					t.Errorf("%s:%d contains %q, which must not appear in published documentation:\n\t%s",
						d.path, i+1, bad, strings.TrimSpace(line))
				}
			}
		}
	}
}

func BenchmarkDocCorpusScan(b *testing.B) {
	var bodies []string
	root := filepath.Join(docsDir, "docs")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".md" {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		bodies = append(bodies, string(data))
		return nil
	})
	if err != nil {
		b.Skipf("documentation unavailable: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, body := range bodies {
			_ = flatten(body)
		}
	}
}
