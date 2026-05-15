package main

import (
	"os"

	"github.com/bawdo/jellyfish/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
