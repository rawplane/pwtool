package urldiscovery

import (
	"path/filepath"

	"metsuke/internal/audit"
	"metsuke/internal/executil"
	"metsuke/internal/pipeline"
)

// Phase is the URL & endpoint discovery phase.
type Phase struct {
	runner *executil.Runner
	audit  *audit.Logger
}

// New returns a Phase 4 implementation.
func New(runner *executil.Runner, auditLog *audit.Logger) *Phase {
	return &Phase{runner: runner, audit: auditLog}
}

func (p *Phase) Name() string { return "Phase 4: URL & Endpoint Discovery" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if !s.Cfg.Resume {
		return false
	}
	out := filepath.Join(s.OutDir, "urls", "all_urls.txt")
	return pipeline.IsNonEmpty(out)
}
