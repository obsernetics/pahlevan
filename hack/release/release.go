// Package release answers what the project has actually published, as distinct
// from what it intends to publish.
//
// The distinction is the whole point. The Makefile's VERSION is an intention:
// a release PR moves it, and from that moment CHANGELOG.md and the website
// announce the version. The tag is the fact: without it there is no GitHub
// release, no image, and nothing anyone can install.
//
// Those two drifted apart six times. Each time the site spent hours or days
// telling readers to `docker pull` a tag that did not exist, because every
// published claim was derived from the intention. This package exists so the
// claims can be derived from the fact instead: when a release is merged but
// not yet tagged, the site keeps advertising the previous version, which is
// merely stale rather than false.
package release

import (
	"bytes"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

// Lister reports the candidate version tags. It is an injection point so the
// generators' tests do not need a git repository with a particular tag history.
type Lister func() ([]string, error)

// GitTags lists the version tags in the checkout at root.
func GitTags(root string) Lister {
	return func() ([]string, error) {
		cmd := exec.Command("git", "-C", root, "tag", "--list", "v*")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			// "exit status 128" on its own tells an operator nothing. The two
			// real causes are a directory that is not a repository and a
			// checkout without tags, and the fix differs, so name both.
			return nil, fmt.Errorf(
				"listing git tags in %s: %w: %s. The published version is derived from tags, "+
					"so this has to be a git checkout that fetched them: in CI set `fetch-tags: true` "+
					"on actions/checkout",
				root, err, strings.TrimSpace(stderr.String()))
		}
		return strings.Fields(string(out)), nil
	}
}

// Fixed is a Lister over a known set, for tests.
func Fixed(tags ...string) Lister {
	return func() ([]string, error) { return tags, nil }
}

// isRelease reports whether a tag names a version this should advertise.
//
// Two rejections that semver.IsValid alone does not make:
//
// "v3.6" and "v3" are valid to semver.IsValid, which tolerates a missing minor
// or patch. They are not tags this project cuts, and treating "v3.6" as a
// release would have it sort above "v3.5.1" and below "v3.6.0", so it could
// become Latest and send a reader to an image tag that does not exist.
//
// A prerelease is excluded even though it is a perfectly valid version,
// because semver orders v3.7.0-rc.1 above v3.6.0. It is a real ordering and
// the wrong answer here: pushing a release candidate would move the install
// command the website hands to everyone onto the candidate.
func isRelease(tag string) bool {
	return semver.IsValid(tag) &&
		semver.Canonical(tag) == tag &&
		semver.Prerelease(tag) == ""
}

// Published is the set of versions that exist as tags.
type Published struct {
	has    map[string]bool
	sorted []string // newest first
}

// Load collects the published versions.
//
// An empty result is an error rather than an empty set. A checkout with no tags
// is the normal state of a shallow CI clone, and the failure it would otherwise
// cause is silent: every claim would quietly fall back to "nothing is
// published". Failing here, with the fix named, is the behaviour that cannot be
// mistaken for an answer.
func Load(l Lister) (Published, error) {
	tags, err := l()
	if err != nil {
		return Published{}, err
	}

	p := Published{has: make(map[string]bool, len(tags))}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if !isRelease(t) {
			// A tag like "v3.6", "vlatest" or "v3.7.0-rc.1" is not a release
			// this should advertise. Skipped rather than rejected: a repo is
			// allowed to carry tags that are not releases.
			continue
		}
		if p.has[t] {
			continue
		}
		p.has[t] = true
		p.sorted = append(p.sorted, t)
	}
	if len(p.sorted) == 0 {
		return Published{}, fmt.Errorf(
			"no valid version tags found, so nothing can be said about what is published. " +
				"In CI this usually means the checkout did not fetch tags: set `fetch-tags: true` " +
				"on actions/checkout. Publishing a version derived from the Makefile instead is how " +
				"the site came to advertise releases that were never tagged")
	}
	sort.Slice(p.sorted, func(i, j int) bool {
		return semver.Compare(p.sorted[i], p.sorted[j]) > 0
	})
	return p, nil
}

// Latest is the newest published version, with its leading "v".
func (p Published) Latest() string {
	if len(p.sorted) == 0 {
		return ""
	}
	return p.sorted[0]
}

// Has reports whether a version is published. It accepts both "3.6.0" and
// "v3.6.0", because CHANGELOG.md headings carry no "v" and tags do.
func (p Published) Has(version string) bool {
	v := strings.TrimSpace(version)
	if v == "" {
		return false
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return p.has[v]
}

// Len is the number of published versions.
func (p Published) Len() int { return len(p.sorted) }

// All returns the published versions, newest first.
func (p Published) All() []string {
	out := make([]string, len(p.sorted))
	copy(out, p.sorted)
	return out
}
