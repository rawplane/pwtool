// Package nuclei implements Phase 8: vulnerability scanning via nuclei.
package nuclei

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

func (p *Phase) Name() string { return "Phase 8: Vulnerability Scanning (nuclei)" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if s.Cfg.PassiveOnly {
		return true
	}
	if !s.Cfg.Resume {
		return false
	}
	out := filepath.Join(s.OutDir, "vulns", "nuclei_results.jsonl")
	return pipeline.IsNonEmpty(out)
}

func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	if s.Cfg.PassiveOnly {
		s.Log.Info("passive-only mode: skipping nuclei (sends requests to targets)")
		return nil
	}
	in := filepath.Join(s.OutDir, "httpx", "live_hosts.txt")
	vulnsDir := filepath.Join(s.OutDir, "vulns")
	if err := os.MkdirAll(vulnsDir, 0o700); err != nil {
		return err
	}
	out := filepath.Join(vulnsDir, "nuclei_results.jsonl")

	if !pipeline.IsNonEmpty(in) {
		s.Log.Warn("No live hosts for nuclei, skipping.")
		return nil
	}

	severity := s.Cfg.NucleiSeverity
	if s.Cfg.FullScan {
		severity = "info,low,medium,high,critical"
	}

	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] nuclei -l %s -severity %s -jsonl -o %s", in, severity, out)
		return nil
	}

	if s.Cfg.UpdateTemplates {
		s.Log.Info("Updating nuclei templates...")
		if err := p.runner.RunWithTimeout(0, executil.Cmd{
			Name: "nuclei",
			Args: []string{"-update-templates"},
		}); err != nil && err != executil.ErrDryRun {
			s.Log.Warn("Template update failed (check connectivity): %v", err)
		}
	} else {
		s.Log.Warn("Templates not updated this run — use --update-templates or run 'nuclei -update-templates' periodically.")
	}

	args := []string{"-l", in, "-severity", severity, "-silent"}
	if s.Cfg.NoInteractsh {
		args = append(args, "-ni")
	}
	if s.Cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", s.Cfg.RateLimit))
	}
	if s.Cfg.NucleiTags != "" {
		args = append(args, "-tags", s.Cfg.NucleiTags)
	}
	args = append(args, "-jsonl", "-o", out)

	s.Log.Info("Running nuclei (severity: %s)...", severity)
	if err := p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "nuclei",
		Args: args,
	}); err != nil && err != executil.ErrDryRun {
		s.Log.Warn("nuclei failed: %v", err)
	}

	count := pipeline.CountLines(out)
	if count > 0 {
		s.Log.Warn("%d finding(s) detected! Check %s", count, out)
		if s.Notifier != nil {
			s.Notifier.Send(ctx, fmt.Sprintf("⚠️ nuclei found %d potential vulnerabilities on %s", count, s.Cfg.Domain))
		}
	} else {
		s.Log.OK("No significant findings from nuclei")
	}
	return nil
}
