// Package pipeline implements the metsuke execution engine: a sequence of
// phases, each implementing the Phase interface, run either sequentially or
// with a controlled concurrency branch (port scan + URL discovery in
// --parallel mode).
package pipeline

import (
	"context"

	"metsuke/internal/audit"
	"metsuke/internal/config"
	"metsuke/internal/executil"
	"metsuke/internal/logutil"
	"metsuke/internal/notify"
)

// Phase is the contract every metsuke phase implements.
type Phase interface {
	// Name returns the human-readable phase name.
	Name() string
	// Run executes the phase. An error is logged but does NOT abort the
	// pipeline — the engine continues to the next phase.
	Run(ctx context.Context, state *State) error
	// ShouldSkip returns true if the phase's output already exists and
	// --resume is enabled, or if the phase is not applicable.
	ShouldSkip(state *State) bool
}

// State is the shared context every phase receives.
type State struct {
	Cfg      *config.Config
	Log      *logutil.Logger
	Audit    *audit.Logger
	Runner   *executil.Runner
	Notifier *notify.Notifier

	// OutDir is the fully-resolved output directory.
	OutDir string

	// Headers is the list of session headers for crawling.
	Headers []string
}

// NewState constructs a State from the given dependencies.
func NewState(
	cfg *config.Config,
	log *logutil.Logger,
	auditLog *audit.Logger,
	runner *executil.Runner,
	notifier *notify.Notifier,
	outDir string,
) *State {
	return &State{
		Cfg:      cfg,
		Log:      log,
		Audit:    auditLog,
		Runner:   runner,
		Notifier: notifier,
		OutDir:   outDir,
	}
}

// Subdir returns the full path of a subdirectory under the output dir.
func (s *State) Subdir(parts ...string) string {
	return joinPath(s.OutDir, parts...)
}
