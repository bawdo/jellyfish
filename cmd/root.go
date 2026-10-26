package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
	"github.com/bawdo/jellyfish/internal/output"
)

// Execute runs the CLI. The returned int is the process exit code.
func Execute() int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return runRoot(ctx, newRootCmd(), os.Args[1:])
}

// runRoot executes root with args and prints any error to root's stderr
// itself (root sets SilenceErrors), so the text can be sanitised first.
// Errors often carry server-controlled text (an Iru APIError message is the
// response detail or raw body, Gmail errors likewise), and an embedded
// ESC/OSC sequence would otherwise be interpreted by the admin's terminal.
// The output format matches what cobra prints: "Error: <msg>", plus the
// "Run '<cmd> --help' for usage." hint for command-lookup failures.
//
// Everything else written to root's stderr goes through
// output.NewTerminalWriter too: per-recipient status lines, the user picker
// and progress lines all carry user records or upstream error text.
//
// A nil args is treated as no arguments: cobra would otherwise fall back to
// os.Args, which under `go test` are the test binary's own flags.
func runRoot(ctx context.Context, root *cobra.Command, args []string) int {
	if args == nil {
		args = []string{}
	}
	root.SetArgs(args)
	root.SetErr(output.NewTerminalWriter(root.ErrOrStderr()))
	cmd, err := root.ExecuteContextC(ctx)
	if err != nil {
		if cmd == nil {
			cmd = root
		}
		w := root.ErrOrStderr()
		_, _ = fmt.Fprintln(w, cmd.ErrPrefix(), output.SanitiseTerminalText(err.Error()))
		// cobra adds the usage hint only when resolving the command itself
		// failed (unknown command); Find is side-effect free, so re-run it
		// to tell that case apart from a RunE or flag-parse error.
		if _, _, findErr := root.Find(args); findErr != nil {
			_, _ = fmt.Fprintf(w, "Run '%v --help' for usage.\n", cmd.CommandPath())
		}
	}
	return classifyError(err)
}

// classifyError maps an error to the documented exit codes.
//
//	0 - success
//	1 - user error
//	2 - auth/permissions
//	3 - not found
//	4 - upstream / network
func classifyError(err error) int {
	if err == nil {
		return 0
	}
	switch {
	case errors.Is(err, iru.ErrUnauthorized), errors.Is(err, iru.ErrForbidden):
		return 2
	case errors.Is(err, iru.ErrNotFound):
		return 3
	case errors.Is(err, iru.ErrRateLimited), errors.Is(err, iru.ErrCursorStalled):
		return 4
	case errors.Is(err, gmail.ErrUnauthorized), errors.Is(err, gmail.ErrForbidden):
		return 2
	case errors.Is(err, gmail.ErrRateLimited), errors.Is(err, gmail.ErrUpstream):
		return 4
	case errors.Is(err, email.ErrRender):
		return 1
	}
	if isNetworkError(err) {
		return 4
	}
	var apiErr *iru.APIError
	if errors.As(err, &apiErr) {
		if apiErr.Status >= 500 {
			return 4
		}
	}
	return 1
}

// isNetworkError reports whether err is a genuine transport failure: DNS
// failure, connection refused or reset, a timeout, or the server hanging up
// mid-request. It matches the concrete net error types rather than any
// net.Error, because *url.Error is itself a net.Error and wraps failures
// that are not the network's fault: our own CheckRedirect refusal (foreign
// host or scheme downgrade) and malformed URLs. A cancelled context is the
// user interrupting, not an upstream fault, so it stays a plain exit 1 even
// when it surfaces wrapped in a *net.OpError.
func isNetworkError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	// A *url.Error's Timeout delegates to the error it wraps, so this is
	// true only for a real timeout (http.Client.Timeout and the like).
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// The server closing the connection before or during the response.
	var urlErr *url.Error
	if errors.As(err, &urlErr) && (errors.Is(urlErr.Err, io.EOF) || errors.Is(urlErr.Err, io.ErrUnexpectedEOF)) {
		return true
	}
	return false
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "jellyfish",
		Short:         "CLI for the Iru (Kandji) Endpoint Management API",
		SilenceUsage:  true,
		SilenceErrors: true, // runRoot prints errors, sanitised
	}

	root.PersistentFlags().StringP("output", "o", "table", "Output format: table, json, yaml, csv")
	root.PersistentFlags().BoolP("verbose", "v", false, "Verbose logging to stderr")
	root.PersistentFlags().String("config", "", "Override config file path (default ~/.config/jellyfish/config.yml)")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newConfigureCmd())
	root.AddCommand(newVulnsCmd())
	root.AddCommand(newUserCmd())
	root.AddCommand(newUsersCmd())
	root.AddCommand(newOverviewCmd())
	applyHelpBareword(root)
	return root
}

// applyHelpBareword walks cmd and every descendant so that the literal token
// "help" as the first positional argument prints that command's help and
// returns without invoking RunE. This makes `jellyfish overview help` work
// alongside the standard `jellyfish overview --help`, idiomatic across the
// CLI. Parent commands with no RunE already fall through to help when an
// unmatched positional arg is passed; the wrapper is only load-bearing for
// leaves.
func applyHelpBareword(cmd *cobra.Command) {
	orig := cmd.RunE
	if orig != nil {
		cmd.RunE = func(c *cobra.Command, args []string) error {
			if len(args) > 0 && args[0] == "help" {
				return c.Help()
			}
			return orig(c, args)
		}
	}
	for _, sub := range cmd.Commands() {
		applyHelpBareword(sub)
	}
}
