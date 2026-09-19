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

// Hub marks PahlevanPolicy as the conversion hub for its kind.
func (*PahlevanPolicy) Hub() {}

// Hub marks ContainerProfile as the conversion hub for its kind.
func (*ContainerProfile) Hub() {}

// Hub marks AttackSurface as the conversion hub for its kind.
func (*AttackSurface) Hub() {}
