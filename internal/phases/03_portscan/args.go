package portscan

import (
	"fmt"
	"path/filepath"

	"metsuke/internal/pipeline"
)

// buildArgs constructs the naabu command-line from the config.
func buildArgs(s *pipeline.State, in, out string) []string {
	args := []string{"-l", in}
	if s.Cfg.FullScan {
		args = append(args, "-p", "-")
	} else {
		args = append(args, "-top-ports", "1000")
	}
	if !isRoot() {
		args = append(args, "-scan-type", "c")
	}
	if s.Cfg.RateLimit > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", s.Cfg.RateLimit))
	} else {
		args = append(args, "-rate", "1000")
	}
	args = append(args, "-silent", "-o", filepath.Join(out, "open_ports.txt"))
	return args
}
