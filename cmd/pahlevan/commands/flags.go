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
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// One concept, two spellings.
//
// "Keep running and show me new things" is spelled --follow on logs and events
// (a byte stream, like kubectl logs -f) and --watch on metrics and policy
// status (a table that is re-rendered, like kubectl get -w). Both spellings
// are right for their command and both are wrong for the other one, so a user
// who learned one of them types it at the other and gets
//
//	Error: unknown flag: --watch
//
// for a concept the command plainly supports. Renaming either would break
// every script and every muscle memory already built on it, so instead each
// command accepts the other word as an alias for its own flag. The primary
// spelling is the one that appears in help; the alias exists so that nobody
// has to remember which drawer this particular command was filed in.
//
// The shorthands cannot be aliased this way - pflag resolves -f and -w through
// a separate single-letter table - so only the long forms are interchangeable.

// aliasFlagNames makes the given alternative names resolve to a canonical flag
// on this command. aliases maps the alternative spelling to the real flag.
func aliasFlagNames(cmd *cobra.Command, aliases map[string]string) {
	cmd.Flags().SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if canonical, ok := aliases[name]; ok {
			return pflag.NormalizedName(canonical)
		}
		return pflag.NormalizedName(name)
	})
}

// acceptWatchAsFollow lets --watch be typed at a command whose flag is
// --follow.
func acceptWatchAsFollow(cmd *cobra.Command) {
	aliasFlagNames(cmd, map[string]string{"watch": "follow"})
}

// acceptFollowAsWatch lets --follow be typed at a command whose flag is
// --watch.
func acceptFollowAsWatch(cmd *cobra.Command) {
	aliasFlagNames(cmd, map[string]string{"follow": "watch"})
}
