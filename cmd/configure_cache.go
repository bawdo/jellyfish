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
			cfgPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			if cfgPath == "" {
				cfgPath, err = config.DefaultPath()
				if err != nil {
					return err
				}
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

	r := bufio.NewReader(o.Stdin)

	current := ""
	if prof.CacheTTLMinutes > 0 {
		current = strconv.Itoa(prof.CacheTTLMinutes)
	}

	var chosen int
	var setExplicitly bool
	cleared := false

	for attempt := 1; attempt <= configureEmailMaxAttempts; attempt++ {
		line, err := promptWithDefault(o.Stdout, r, "Cache TTL in minutes", current)
		if err != nil {
			return err
		}
		switch line {
		case current:
			// User pressed Enter; keep whatever we had (which may be "").
			if prof.CacheTTLMinutes == 0 {
				_, _ = fmt.Fprintln(o.Stdout, "Cache TTL unchanged (using built-in default)")
				return nil
			}
			_, _ = fmt.Fprintf(o.Stdout, "Cache TTL unchanged (%d minutes)\n", prof.CacheTTLMinutes)
			return nil
		case "":
			// User typed "-" (collapsed to empty by promptWithDefault) on a
			// profile that has a value set. When current=="" (no value set)
			// this case is unreachable because the `current` case above
			// matches first (Go evaluates cases in source order), so typing
			// "-" on an unset TTL is treated as a no-op keep.
			cleared = true
		default:
			n, perr := strconv.Atoi(line)
			if perr != nil {
				_, _ = fmt.Fprintf(o.Stderr, "invalid number: %v\n", perr)
				continue
			}
			if vErr := config.ValidateCacheTTLMinutes(n); vErr != nil {
				_, _ = fmt.Fprintln(o.Stderr, vErr)
				continue
			}
			chosen = n
			setExplicitly = true
		}
		break
	}

	if !cleared && !setExplicitly {
		return fmt.Errorf("invalid cache TTL after %d attempts", configureEmailMaxAttempts)
	}

	if cleared {
		prof.CacheTTLMinutes = 0
	} else {
		prof.CacheTTLMinutes = chosen
	}
	file["default"] = prof

	if err := config.Save(o.ConfigPath, file); err != nil {
		return err
	}

	if cleared {
		_, _ = fmt.Fprintf(o.Stdout, "Cache TTL cleared (using built-in default; saved to %s)\n", o.ConfigPath)
	} else {
		_, _ = fmt.Fprintf(o.Stdout, "Cache TTL set to %d minutes (saved to %s)\n", chosen, o.ConfigPath)
	}
	return nil
}
