package cmd

import (
	"context"
	"errors"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
)

// Execute runs the CLI. The returned int is the process exit code.
func Execute() int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	err := newRootCmd().ExecuteContext(ctx)
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
	case errors.Is(err, iru.ErrRateLimited):
		return 4
	case errors.Is(err, gmail.ErrUnauthorized), errors.Is(err, gmail.ErrForbidden):
		return 2
	case errors.Is(err, gmail.ErrRateLimited), errors.Is(err, gmail.ErrUpstream):
		return 4
	case errors.Is(err, email.ErrRender):
		return 1
	}
	var apiErr *iru.APIError
	if errors.As(err, &apiErr) {
		if apiErr.Status >= 500 {
			return 4
		}
	}
	return 1
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "jellyfish",
		Short:         "CLI for the Iru (Kandji) Endpoint Management API",
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	root.PersistentFlags().StringP("output", "o", "table", "Output format: table, json, yaml, csv")
	root.PersistentFlags().BoolP("verbose", "v", false, "Verbose logging to stderr")
	root.PersistentFlags().String("config", "", "Override config file path (default ~/.config/jellyfish/config.yml)")
	root.PersistentFlags().String("profile", "default", "Profile name (reserved; only 'default' is honoured in v1)")

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
