// Package releasetest builds git repositories for the site generators' tests.
//
// Both generators now decide what is published by asking git for tags, so a
// fixture built in a bare temp directory is a tree where nothing has ever been
// released. That is not the state these tests mean to describe, and the
// resulting failure is confusing rather than informative, so the fixture has to
// be a real repository with real tags.
//
// It is a separate package so the two generators share one copy instead of
// drifting, and so the production packages do not import "testing".
package releasetest

import (
	"os"
	"os/exec"
	"testing"
)

// InitRepo makes root a git repository with a tag for each version.
//
// Versions may be given with or without a leading "v"; the tag always carries
// one, because that is the form the repository uses.
func InitRepo(tb testing.TB, root string, versions ...string) {
	tb.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		tb.Skip("git is not available, and the generators need tags to tell a shipped version from a planned one")
	}

	run := func(args ...string) {
		tb.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		// Set identity in the environment rather than relying on the machine's
		// git config, which in CI is usually unset and makes `git commit` fail
		// with a message about who you are.
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=releasetest", "GIT_AUTHOR_EMAIL=releasetest@example.com",
			"GIT_COMMITTER_NAME=releasetest", "GIT_COMMITTER_EMAIL=releasetest@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			tb.Fatalf("git %v in %s: %v: %s", args, root, err, out)
		}
	}

	run("init", "-q")
	// A tag needs something to point at, and these fixtures have nothing
	// committed: the files are written straight into the directory.
	run("commit", "--allow-empty", "-q", "-m", "releasetest")

	for _, v := range versions {
		if v == "" {
			continue
		}
		if v[0] != 'v' {
			v = "v" + v
		}
		run("tag", v)
	}
}
