// Package report implements Phase 10: summary report generation.
package report

import "metsuke/internal/pipeline"

type Phase struct{}

func New() *Phase { return &Phase{} }

func (p *Phase) Name() string { return "Summary" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool { return false }

func countLine(path string) int { return pipeline.CountLines(path) }
