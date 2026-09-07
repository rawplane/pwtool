// Package httpxprobe implements Phase 2: live host probing via httpx.
package httpxprobe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"metsuke/internal/audit"
	"metsuke/internal/executil"
	"metsuke/internal/pipeline"
)

// Phase is the httpx live-host probing phase.
type Phase struct {
	runner *executil.Runner
	audit  *audit.Logger
}

// New returns a Phase 2 implementation.
func New(runner *executil.Runner, auditLog *audit.Logger) *Phase {
	return &Phase{runner: runner, audit: auditLog}
}

func (p *Phase) Name() string { return "Phase 2: Live Host Probing (httpx)" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if !s.Cfg.Resume {
		return false
	}
	out := filepath.Join(s.OutDir, "httpx", "httpx_full.json")
	return pipeline.IsNonEmpty(out)
}

// Run executes the httpx probing phase.
func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	if s.Cfg.PassiveOnly {
		s.Log.Info("passive-only mode: skipping live host probing (sends requests to targets)")
		return nil
	}
	in := filepath.Join(s.OutDir, "subdomains", "all_subdomains.txt")
	out := filepath.Join(s.OutDir, "httpx")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	if !pipeline.IsNonEmpty(in) {
		s.Log.Warn("No subdomains to probe, skipping this phase.")
		return nil
	}
	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] httpx -l %s -threads %d -timeout %d -status-code -title -tech-detect -cdn -json -o %s/httpx_full.json",
			in, s.Cfg.Threads, s.Cfg.Timeout, out)
		return nil
	}

	args := buildArgs(s, in, out)
	if err := p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "httpx",
		Args: args,
	}); err != nil && err != executil.ErrDryRun {
		s.Log.Warn("httpx failed: %v", err)
	}

	if err := extractLiveHosts(out); err != nil {
		s.Log.Warn("extract live hosts: %v", err)
	}
	count := pipeline.CountLines(filepath.Join(out, "live_hosts.txt"))
	cdnCount := pipeline.CountLines(filepath.Join(out, "cdn_hosts.txt"))
	s.Log.OK("%d live hosts detected → %s/live_hosts.txt", count, out)
	if cdnCount > 0 {
		s.Log.Info("Found %d hosts behind CDN/WAF", cdnCount)
	}
	if s.Notifier != nil {
		s.Notifier.Send(ctx, fmt.Sprintf("Live host probing completed: %d live hosts", count))
	}
	return nil
}
