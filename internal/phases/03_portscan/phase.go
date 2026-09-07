// Package portscan implements Phase 3: port scanning via naabu.
package portscan

import (
	"context"
	"os"
	"os/user"
	"path/filepath"

	"metsuke/internal/audit"
	"metsuke/internal/executil"
	"metsuke/internal/pipeline"
)

// Phase is the port scanning phase.
type Phase struct {
	runner *executil.Runner
	audit  *audit.Logger
}

// New returns a Phase 3 implementation.
func New(runner *executil.Runner, auditLog *audit.Logger) *Phase {
	return &Phase{runner: runner, audit: auditLog}
}

func (p *Phase) Name() string { return "Phase 3: Port Scanning (naabu)" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if !s.Cfg.Resume {
		return false
	}
	out := filepath.Join(s.OutDir, "ports", "open_ports.txt")
	return pipeline.IsNonEmpty(out)
}

// Run executes the naabu port scan phase.
func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	if s.Cfg.PassiveOnly {
		s.Log.Info("passive-only mode: skipping port scan")
		return nil
	}
	out := filepath.Join(s.OutDir, "ports")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}

	in := prepareTargets(s)
	if in == "" || !pipeline.IsNonEmpty(in) {
		s.Log.Warn("No targets for port scan, skipping.")
		return nil
	}

	if s.Cfg.DryRun {
		portFlag := "-top-ports 1000"
		if s.Cfg.FullScan {
			portFlag = "-p -"
		}
		s.Log.Info("[DRY-RUN] naabu -l %s %s -silent -o %s/open_ports.txt", in, portFlag, out)
		return nil
	}

	args := buildArgs(s, in, out)
	if err := p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "naabu",
		Args: args,
	}); err != nil && err != executil.ErrDryRun {
		s.Log.Warn("naabu failed: %v", err)
	}

	count := pipeline.CountLines(filepath.Join(out, "open_ports.txt"))
	s.Log.OK("%d open host:port combinations → %s/open_ports.txt", count, out)
	return nil
}

// isRoot returns true if the current process is running as root.
func isRoot() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0"
}
