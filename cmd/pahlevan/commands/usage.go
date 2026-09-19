/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// The two ways a command can fail before it does any work - no cluster, and a
// missing argument - are the two failures a user hits on their first day. Both
// used to answer with a sentence that named nothing they could act on, so both
// are built here, once, from the command's own metadata.

// errClientsNotReady is the shared message for commands that need a cluster.
//
// The "not initialized" wording is load-bearing: it is what tells a reader the
// CLI never got as far as talking to an API server, so the problem is local
// configuration rather than a cluster that said no.
func errClientsNotReady() error {
	return fmt.Errorf("kubernetes clients are not initialized - no cluster connection\n%s", ClusterHint())
}

// NamedArgs validates positional arguments and, when they are wrong, says
// which argument is missing and how the command is spelled.
//
// cobra.ExactArgs(1) answers "accepts 1 arg(s), received 0". That is true and
// useless: it does not name the argument, and because the root sets
// SilenceUsage (so a failed cluster call does not dump a screen of flags) the
// usage line is not printed either. A user who typed `pahlevan policy get` is
// then told a number and left to guess. This prints the one line they need.
func NamedArgs(names ...string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == len(names) {
			return nil
		}
		if len(args) < len(names) {
			missing := names[len(args):]
			return fmt.Errorf("missing %s\nUsage: %s",
				joinNames(missing), cmd.UseLine())
		}
		return fmt.Errorf("unexpected argument %q: %s takes %s\nUsage: %s",
			args[len(names)], cmd.CommandPath(), countArgs(names), cmd.UseLine())
	}
}

// joinNames renders the missing argument names the way the Use line spells
// them, so the error and the usage line below it use the same words.
func joinNames(names []string) string {
	quoted := make([]string, 0, len(names))
	for _, n := range names {
		quoted = append(quoted, "<"+strings.Trim(n, "<>")+">")
	}
	switch len(quoted) {
	case 1:
		return "argument " + quoted[0]
	case 2:
		return "arguments " + quoted[0] + " and " + quoted[1]
	default:
		return "arguments " + strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
	}
}

func countArgs(names []string) string {
	if len(names) == 1 {
		return "one argument"
	}
	return fmt.Sprintf("%d arguments", len(names))
}

// OneOfArgs validates a single positional argument against a fixed set, naming
// the set in the error. cobra.OnlyValidArgs does this too, but its message
// omits the usage line, which is where the shell name belongs.
func OneOfArgs(name string, valid ...string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := NamedArgs(name)(cmd, args); err != nil {
			return err
		}
		for _, v := range valid {
			if args[0] == v {
				return nil
			}
		}
		return fmt.Errorf("invalid %s %q: expected one of %s\nUsage: %s",
			strings.Trim(name, "<>"), args[0], strings.Join(valid, ", "), cmd.UseLine())
	}
}
