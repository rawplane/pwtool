// Package takeover implements Phase 6: subdomain takeover check via nuclei.
package takeover

import (
	"context"
	"fmt"
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

func (p *Phase) Name() string { return "Phase 6: Subdomain Takeover Check" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if s.Cfg.PassiveOnly {
		return true
	}
	if !s.Cfg.Resume {
		return false
	}
	out := filepath.Join(s.OutDir, "vulns", "takeover_results.jsonl")
	return pipeline.IsNonEmpty(out)
}

func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	if s.Cfg.PassiveOnly {
		s.Log.Info("passive-only mode: skipping takeover check")
		return nil
	}
	in := filepath.Join(s.OutDir, "subdomains", "all_subdomains.txt")
	vulnsDir := filepath.Join(s.OutDir, "vulns")
	if err := os.MkdirAll(vulnsDir, 0o700); err != nil {
		return err
	}
	out := filepath.Join(vulnsDir, "takeover_results.jsonl")

	if !pipeline.IsNonEmpty(in) {
		s.Log.Warn("No subdomains, skipping takeover check.")
		return nil
	}

	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] nuclei -l %s -t http/takeovers/ -silent -jsonl -o %s", in, out)
		return nil
	}

	s.Log.Info("Running nuclei takeover templates...")
	args := []string{"-l", in, "-t", "http/takeovers/", "-silent", "-jsonl"}
	if s.Cfg.NoInteractsh {
		args = append(args, "-ni")
	}
	if s.Cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", s.Cfg.RateLimit))
	}
	args = append(args, "-o", out)

	if err := p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "nuclei",
		Args: args,
	}); err != nil && err != executil.ErrDryRun {
		s.Log.Warn("nuclei takeover failed: %v", err)
	}

	count := pipeline.CountLines(out)
	if count > 0 {
		s.Log.Warn("%d possible subdomain takeover(s) detected!", count)
		if s.Notifier != nil {
			s.Notifier.Send(ctx, fmt.Sprintf("🚨 %d possible subdomain takeover(s) on %s", count, s.Cfg.Domain))
		}
	} else {
		s.Log.OK("No indication of subdomain takeover")
	}
	return nil
}
