package main

import (
	"fmt"
	"os"

	"metsuke/internal/version"
)

// banner is the ASCII art banner printed at startup, mirroring the bash
// version's print_banner(). The art is a simplified rendition of the 目付
// (metsuke) inspector motif.
func printBanner() {
	cyan := "\033[0;36m"
	bold := "\033[1m"
	nc := "\033[0m"

	fmt.Fprintf(os.Stdout, "%s", cyan)
	fmt.Fprintf(os.Stdout, "┌─────────────────────────────────────────────┐\n")
	fmt.Fprintf(os.Stdout, "│              %s 目 付 (metsuke) %s            │\n", bold, cyan)
	fmt.Fprintf(os.Stdout, "│       \"authorize first, then act\"            │\n")
	fmt.Fprintf(os.Stdout, "│  recon pipeline v%s — modular · authorized · audited │\n", version.Version)
	fmt.Fprintf(os.Stdout, "└─────────────────────────────────────────────┘\n")
	fmt.Fprintf(os.Stdout, "%s\n", nc)
}
