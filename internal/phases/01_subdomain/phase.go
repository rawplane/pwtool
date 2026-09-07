package subdomain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"metsuke/internal/audit"
	"metsuke/internal/executil"
	"metsuke/internal/pipeline"
)

// Phase is the subdomain enumeration phase.
type Phase struct {
	runner *executil.Runner
	audit  *audit.Logger
}

// New returns a Phase 1 implementation.
func New(runner *executil.Runner, auditLog *audit.Logger) *Phase {
	return &Phase{runner: runner, audit: auditLog}
}

func (p *Phase) Name() string { return "Phase 1: Subdomain Enumeration" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if !s.Cfg.Resume {
		return false
	}
	out := filepath.Join(s.OutDir, "subdomains", "all_subdomains.txt")
	info, err := os.Stat(out)
	return err == nil && info.Size() > 0
}

// Run executes the subdomain enumeration phase.
func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	out := filepath.Join(s.OutDir, "subdomains")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return fmt.Errorf("create subdomain dir: %w", err)
	}

	if s.Cfg.DryRun {
		p.dryRun(s, out)
		return nil
	}

	// subfinder
	subfinderOut := filepath.Join(out, "subfinder.txt")
	if err := p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "subfinder",
		Args: []string{"-d", s.Cfg.Domain, "-all", "-silent", "-o", subfinderOut},
	}); err != nil && err != executil.ErrDryRun {
		s.Log.Warn("subfinder failed: %v", err)
	}

	// assetfinder (optional)
	p.runAssetfinder(s, out)

	// crt.sh
	crtshOut := filepath.Join(out, "crtsh.txt")
	if err := fetchCrtsh(ctx, s.Cfg.Domain, crtshOut); err != nil {
		s.Log.Warn("crt.sh query failed: %v", err)
	}

	// Merge + scope filter + exclude-sub
	allOut := filepath.Join(out, "all_subdomains.txt")
	if err := p.mergeAndFilter(out, allOut, s); err != nil {
		return err
	}

	count := countLines(allOut)
	s.Log.OK("%d unique in-scope subdomains → %s", count, allOut)
	if s.Notifier != nil {
		s.Notifier.Send(ctx, fmt.Sprintf("Subdomain enum completed: %d subdomains found for %s", count, s.Cfg.Domain))
	}
	return nil
}
