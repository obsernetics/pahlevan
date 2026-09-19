package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/obsernetics/pahlevan/pkg/tui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type uiOptions struct {
	grpcAddr string
	replay   string
	capacity int
	noTUI    bool
}

// NewUICommand builds `pahlevan ui`.
//
// The interactive view is a separate command rather than a flag on `events`,
// and every existing command keeps its exact output. A tool whose behaviour
// changes depending on whether stdout happens to be a terminal is a tool whose
// scripts break when somebody runs them from a CI job instead of a shell.
func NewUICommand() *cobra.Command {
	opts := &uiOptions{}

	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Watch events, workloads and coverage in an interactive terminal view",
		Long: strings.TrimSpace(`
Open an interactive view of what the agents are reporting: a live event
stream, per-workload counts of what was observed and what was refused, and
the ATT&CK coverage table.

The view is a reader. It never changes a policy, a mode or a profile, so it
cannot be the thing that turns enforcement off during an incident.

Without a terminal - piped, redirected, under CI, or with --no-tui - this
prints a plain summary instead of drawing a screen, because a program that
writes escape codes into a pipe is worse than one with no interface at all.
`),
		Example: strings.TrimSpace(`
  # Watch a node's agent
  pahlevan ui --grpc localhost:9090

  # Replay a captured JSON-lines file, no cluster needed
  pahlevan ui --replay events.jsonl

  # In a pipeline: prints a summary, draws nothing
  pahlevan ui --replay events.jsonl | tee report.txt
`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUI(cmd.Context(), opts, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.grpcAddr, "grpc", "localhost:9090", "agent gRPC address to subscribe to")
	f.StringVar(&opts.replay, "replay", "", "replay a JSON-lines event file instead of connecting ('-' for stdin)")
	f.IntVar(&opts.capacity, "capacity", tui.DefaultCapacity, "events retained for the event view")
	f.BoolVar(&opts.noTUI, "no-tui", false, "print a plain summary instead of drawing a screen")

	return cmd
}

// interactive decides whether `pahlevan ui` draws. The flag is the only part
// of the rule that belongs to this command; everything else is the general
// question Interactive answers, and there is exactly one copy of it.
func interactive(opts *uiOptions, out io.Writer) bool {
	if opts.noTUI {
		return false
	}
	return Interactive(out)
}

// Interactive reports whether a full-screen view may be drawn to out. Every
// reason to fall back is checked here rather than scattered, so the rule is
// one thing a reader can verify - and the root command reuses it to decide
// what a bare `pahlevan` does, rather than keeping a second copy that can
// drift from this one.
//
// NO_COLOR is honoured as a fallback signal rather than only as a palette
// switch: somebody who sets it in a pipeline wants plain text, and a
// full-screen alternate-buffer UI is not plain text.
func Interactive(out io.Writer) bool {
	if os.Getenv("CI") != "" || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	// term.IsTerminal rather than a ModeCharDevice test. /dev/null is a
	// character device, so the mode test called `pahlevan ui > /dev/null` a
	// terminal and the program then failed trying to open a TTY that is not
	// there. Asking whether the descriptor is actually a terminal is the
	// question that was meant.
	return term.IsTerminal(int(f.Fd()))
}

func runUI(ctx context.Context, opts *uiOptions, out, errOut io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	src, closeSrc, err := buildSource(opts)
	if err != nil {
		return err
	}
	defer closeSrc()

	if !interactive(opts, out) {
		return runPlain(ctx, src, out)
	}

	m := tui.New(tui.Options{Capacity: opts.capacity, SourceName: src.Describe()})
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx), tea.WithOutput(out))

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	tui.Stream(streamCtx, src, func(msg tea.Msg) { p.Send(msg) })

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("running the interactive view: %w", err)
	}
	return nil
}

// buildSource picks where events come from. A replay needs no cluster, which
// is what makes the view reproducible from a bug report.
func buildSource(opts *uiOptions) (tui.Source, func(), error) {
	if opts.replay == "" {
		return &grpcSource{addr: opts.grpcAddr}, func() {}, nil
	}
	if opts.replay == "-" {
		return &tui.ReaderSource{R: os.Stdin, Name: "stdin"}, func() {}, nil
	}
	f, err := os.Open(opts.replay)
	if err != nil {
		return nil, nil, fmt.Errorf("opening the replay file: %w", err)
	}
	return &tui.ReaderSource{R: f, Name: opts.replay}, func() { _ = f.Close() }, nil
}
