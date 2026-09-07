// Package burp implements Phase 9: Burp Suite Active Scan trigger.
package burp

import (
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

func (p *Phase) Name() string { return "Phase 9: Burp Suite Active Scan Trigger" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if !s.Cfg.BurpActiveScan || s.Cfg.PassiveOnly {
		return true
	}
	if !s.Cfg.Resume {
		return false
	}
	return pipeline.IsNonEmpty(s.OutDir + "/report/burp_scan_response.json")
}
