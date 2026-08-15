package commands

import "github.com/spf13/cobra"

// Which commands need a cluster.
//
// The root command builds Kubernetes clients in PersistentPreRunE, before any
// subcommand runs. That is right for most of them and wrong for the ones that
// read a file or print a constant, and the way it was wrong is the worst
// available: `pahlevan version` failed with
//
//	Error: failed to get Kubernetes config: invalid configuration:
//	no configuration has been provided
//
// That is the first command anyone runs against a new binary, and on a laptop
// with no kubeconfig it says the tool is broken. It is not.
//
// Two commands had already worked around it by overriding PersistentPreRunE
// with a no-op, which works and does not compose: every new offline command has
// to rediscover the trick, and nothing stops one from forgetting. An annotation
// the root checks is one mechanism instead of a convention.

// offlineAnnotation marks a command that must run without a cluster.
const offlineAnnotation = "pahlevan.io/offline"

// Offline marks a command as not needing Kubernetes clients, and returns it so
// it can be used inline where a command is constructed.
func Offline(cmd *cobra.Command) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[offlineAnnotation] = "true"
	return cmd
}

// IsOffline reports whether a command, or any command it sits under, is marked
// offline.
//
// Walking to the parents matters: `pahlevan policy explain` is offline while
// `pahlevan policy` as a group is not, and a subcommand of an offline group
// should inherit it rather than repeat it.
func IsOffline(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Annotations[offlineAnnotation] == "true" {
			return true
		}
	}
	return false
}
