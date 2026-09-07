// Package screenshots implements Phase 7: screenshotting via gowitness.
package screenshots

import (
	"context"
	"os"
	"path/filepath"

	"metsuke/internal/audit"
	"metsuke/internal/executil"
	"metsuke/internal/pipeline"
)

type Phase struct {
	runner *executil.Runner
	audit  *audit.Logger
}

func New(runner *executil.Runner, auditLog *audit.Logger) *Phase {
	return &Phase{runner: runner, audit: auditLog}
}

func (p *Phase) Name() string { return "Phase 7: Screenshotting (optional)" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if s.Cfg.PassiveOnly {
		return true
	}
	if !s.Cfg.Resume {
		return false
	}
	return pipeline.IsNonEmpty(filepath.Join(s.OutDir, "screenshots", ".done"))
}

func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	if s.Cfg.PassiveOnly {
		s.Log.Info("passive-only mode: skipping screenshots")
		return nil
	}
	in := filepath.Join(s.OutDir, "httpx", "live_hosts.txt")
	out := filepath.Join(s.OutDir, "screenshots")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}

	if !executil.CheckInstalled("gowitness") {
		s.Log.Warn("gowitness is not installed, skipping this phase.")
		return nil
	}
	if !pipeline.IsNonEmpty(in) {
		s.Log.Warn("No live hosts, skipping screenshots.")
		return nil
	}

	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] gowitness file -f %s -P %s --no-http", in, out)
		return nil
	}

	s.Log.Info("Taking screenshots of live hosts...")
	if err := p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "gowitness",
		Args: []string{"file", "-f", in, "-P", out, "--no-http"},
	}); err != nil && err != executil.ErrDryRun {
		s.Log.Warn("gowitness failed on some targets: %v", err)
	}
	// Write .done marker file.
	_ = os.WriteFile(filepath.Join(out, ".done"), []byte("done\n"), 0o600)
	s.Log.OK("Screenshots saved to %s", out)
	return nil
}
