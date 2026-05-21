package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
)

type configureCacheOpts struct {
	ConfigPath string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
}

func newConfigureCacheCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cache",
		Short: "Interactively configure the detection/vulnerability cache TTL",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgPath, err := resolveConfigPath(cmd)
			if err != nil {
				return err
			}
			return runConfigureCache(configureCacheOpts{
				ConfigPath: cfgPath,
				Stdin:      cmd.InOrStdin(),
				Stdout:     cmd.OutOrStdout(),
				Stderr:     cmd.ErrOrStderr(),
			})
		},
	}
}

func runConfigureCache(o configureCacheOpts) error {
	file, err := config.Load(o.ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf(`no config found at %s - run "jellyfish configure" first to set up tenant + token`, o.ConfigPath)
		}
		return fmt.Errorf("read config: %w", err)
	}
	prof, ok := file["default"]
	if !ok {
		return errors.New(`no "default" profile yet - run "jellyfish configure" first to set up tenant + token`)
	}

	current := ""
	if prof.CacheTTLMinutes > 0 {
		current = strconv.Itoa(prof.CacheTTLMinutes)
	}

	newTTL, keep, err := promptCacheTTL(o.Stdout, o.Stderr, bufio.NewReader(o.Stdin), current)
	if err != nil {
		return err
	}
	if keep {
		if prof.CacheTTLMinutes == 0 {
			_, _ = fmt.Fprintln(o.Stdout, "Cache TTL unchanged (using built-in default)")
		} else {
			_, _ = fmt.Fprintf(o.Stdout, "Cache TTL unchanged (%d minutes)\n", prof.CacheTTLMinutes)
		}
		return nil
	}

	prof.CacheTTLMinutes = newTTL
	file["default"] = prof
	if err := config.Save(o.ConfigPath, file); err != nil {
		return err
	}

	if newTTL == 0 {
		_, _ = fmt.Fprintf(o.Stdout, "Cache TTL cleared (using built-in default; saved to %s)\n", o.ConfigPath)
	} else {
		_, _ = fmt.Fprintf(o.Stdout, "Cache TTL set to %d minutes (saved to %s)\n", newTTL, o.ConfigPath)
	}
	return nil
}

// promptCacheTTL drives the re-prompt loop. keep is true when the user pressed
// Enter (leave the config untouched); otherwise newTTL is the value to save,
// where 0 means the user cleared it back to the built-in default. Typing "-"
// on a profile with no TTL set reads as Enter, so it is treated as keep.
func promptCacheTTL(stdout, stderr io.Writer, r *bufio.Reader, current string) (newTTL int, keep bool, err error) {
	for attempt := 1; attempt <= configureEmailMaxAttempts; attempt++ {
		line, perr := promptWithDefault(stdout, r, "Cache TTL in minutes", current)
		if perr != nil {
			return 0, false, perr
		}
		switch line {
		case current:
			return 0, true, nil
		case "":
			return 0, false, nil // "-" cleared a set value
		default:
			n, convErr := strconv.Atoi(line)
			if convErr != nil {
				_, _ = fmt.Fprintf(stderr, "invalid number: %v\n", convErr)
				continue
			}
			if vErr := config.ValidateCacheTTLMinutes(n); vErr != nil {
				_, _ = fmt.Fprintln(stderr, vErr)
				continue
			}
			return n, false, nil
		}
	}
	return 0, false, fmt.Errorf("invalid cache TTL after %d attempts", configureEmailMaxAttempts)
}
