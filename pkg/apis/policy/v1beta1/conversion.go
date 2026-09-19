package v1beta1

// This package is the conversion hub. Every other served version converts to
// and from these types rather than to and from each other, so adding a third
// version later costs one pair of functions instead of one pair per existing
// version.
//
// Hub() is the whole contract: it is a marker method that tells
// controller-runtime's conversion machinery which version the spokes speak to.
// The spoke implementations live in the v1alpha1 package, next to the types
// whose quirks they have to know about.
//
// Nothing here converts anything, and that is deliberate. Putting the
// conversion in the spoke means the hub never has to import a version it is
// supposed to outlive.
//
// What serves these conversions, and what does not
//
// The generated CRDs do not declare `spec.conversion.strategy: Webhook`, so
// the API server converts between the two served versions by relabelling
// apiVersion and leaving the fields alone. That is correct here only because
// v1beta1 was deliberately shaped so it is correct: every field v1beta1 keeps
// has the same JSON name, type and nesting as its v1alpha1 counterpart, and
// the only differences are removals of fields nothing read or that could only
// ever be zero. So the API server's no-op conversion and the functions in the
// v1alpha1 package agree on every object.
//
// That shape was a constraint on the design rather than a happy accident. A
// conversion webhook in this project would mean the operator terminating TLS
// for the API server, a certificate to issue and rotate, a caBundle to inject
// into three CRDs, and a new failure mode where an unavailable operator makes
// every existing policy unreadable. For a security tool, that is a larger
// surface than the graduation is worth. The Go conversions exist because
// in-process clients need them, because they are what a webhook would serve if
// one is ever added, and because writing them is what forced the versions to
// be provably compatible - see the tests in the v1alpha1 package.

// Hub marks PahlevanPolicy as the conversion hub for its kind.
func (*PahlevanPolicy) Hub() {}

// Hub marks ContainerProfile as the conversion hub for its kind.
func (*ContainerProfile) Hub() {}

// Hub marks AttackSurface as the conversion hub for its kind.
func (*AttackSurface) Hub() {}
