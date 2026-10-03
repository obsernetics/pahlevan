package adaptive

import (
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// Declared is the entries in a container's allow-set that are there because the
// governing policy declared them, not because the container was observed doing
// them, rendered as the strings a ContainerProfile status reports.
//
// The rendering happens elsewhere, on purpose. internal/policy owns the
// declaration and the spelling of every entry in it - the " (write)" marker, a
// destination as ip:port, a capability without its CAP_ prefix - and this
// package sits below it and cannot import it. What crosses the boundary is the
// finished lists, so the entries the agent seeds into the kernel and the
// entries it reports as declared still come from one place and cannot
// disagree. Two renderings of one declaration would eventually differ, and the
// failure mode of that is a profile claiming a path was declared when the
// allow-set entry was actually refused.
type Declared struct {
	Files        []string
	Destinations []string
	Executables  []string
	Capabilities []string
}

// Empty reports whether nothing was declared.
func (d Declared) Empty() bool {
	return len(d.Files) == 0 && len(d.Destinations) == 0 &&
		len(d.Executables) == 0 && len(d.Capabilities) == 0
}

// DeclarationReporter is the part of a policy resolver that can say what a
// policy declared for a container.
//
// Asserted for rather than added to PolicyResolver. A resolver that cannot
// answer - the fakes in this package's tests, an agent built without policy
// translation - leaves the declared lists empty, which is a true statement
// about a container nothing declared anything for. Requiring the method would
// make every fake implement a reporting concern it has nothing to say about.
type DeclarationReporter interface {
	// DeclaredFor returns what the governing policy declared for a container,
	// keyed by container ID. ok=false means nothing was declared, or the
	// container is not one this resolver has resolved.
	DeclaredFor(containerID string) (Declared, bool)
}

// ReportInto writes the declaration into the profile status fields that report
// it, replacing whatever was there so a re-sync of an unchanged policy writes
// an unchanged status.
//
// The lists are taken as rendered, including their order. internal/policy sorts
// them, matching how the learned lists are written, so a status update is
// driven by the declaration changing rather than by map iteration order.
//
// An empty Declared clears all four fields rather than leaving the last
// declaration standing. A profile must not report an entry the policy no longer
// declares and the kernel no longer has seeded.
func (d Declared) ReportInto(status *policyv1alpha1.ContainerProfileStatus) {
	if status == nil {
		return
	}
	status.DeclaredFiles = copyDeclared(d.Files)
	status.DeclaredNetworkDestinations = copyDeclared(d.Destinations)
	status.DeclaredExecutables = copyDeclared(d.Executables)
	status.DeclaredCapabilities = copyDeclared(d.Capabilities)
}

// copyDeclared copies a list, and reports an empty one as nil so an unset field
// stays unset in the serialized object rather than becoming an empty array.
func copyDeclared(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return append([]string(nil), in...)
}
