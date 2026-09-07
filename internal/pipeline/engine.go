package pipeline

import (
	"context"
	"fmt"

	"metsuke/internal/logutil"
)

// Engine runs a sequence of phases, handling skip-logic, error tolerance,
// and the --parallel concurrency branch (port scan + URL discovery).
type Engine struct {
	state *State
}

// NewEngine constructs an Engine for the given state.
func NewEngine(state *State) *Engine {
	return &Engine{state: state}
}

// RunSequential runs phases one after another. A phase error is logged as a
// warning but does NOT abort the pipeline (mirroring the bash version's
// tolerant `wait`).
func (e *Engine) RunSequential(ctx context.Context, phases []Phase) error {
	for _, p := range phases {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.runOne(ctx, p); err != nil {
			// Log and continue — never abort the whole pipeline on a
			// single phase error.
			e.state.Log.Warn("%s phase exited with errors: %v", p.Name(), err)
		}
	}
	return nil
}

// runOne runs a single phase, honouring ShouldSkip.
func (e *Engine) runOne(ctx context.Context, p Phase) error {
	if p.ShouldSkip(e.state) {
		e.state.Log.OK("Resume enabled: '%s' already done, skipping.", p.Name())
		return nil
	}
	e.state.Log.Section("%s", p.Name())
	if err := p.Run(ctx, e.state); err != nil {
		return err
	}
	return nil
}

// RunParallel runs two phases concurrently under an errgroup. Unlike a raw
// goroutine, errgroup waits for BOTH to finish, and an error in either is
// logged (not returned as a fatal abort) so the rest of the pipeline can
// continue — matching the bash `wait ... || log_warn` behaviour.
func (e *Engine) RunParallel(ctx context.Context, a, b Phase) error {
	e.state.Log.Info("Parallel mode: %s & %s run concurrently.", a.Name(), b.Name())

	errs := make(chan error, 2)
	done := make(chan struct{})

	run := func(p Phase) {
		defer func() { done <- struct{}{} }()
		if p.ShouldSkip(e.state) {
			e.state.Log.OK("Resume enabled: '%s' already done, skipping.", p.Name())
			return
		}
		// NOTE: we do NOT print the section header for parallel phases
		// because they would interleave; the phase's own logs are enough.
		if err := p.Run(ctx, e.state); err != nil {
			errs <- fmt.Errorf("%s: %w", p.Name(), err)
		}
	}

	go run(a)
	go run(b)

	// Wait for both goroutines to finish.
	<-done
	<-done
	close(errs)

	// Log any errors but do not abort.
	for err := range errs {
		e.state.Log.Warn("%v", err)
	}
	return nil
}

// LogPipelineStart writes the pipeline-start audit entry.
func (e *Engine) LogPipelineStart(args []string) {
	if e.state.Audit != nil {
		e.state.Audit.Logf("event=pipeline-start target=%s version=%s config=%s args=%s",
			e.state.Cfg.Domain,
			"dev",
			defaultStr(e.state.Cfg.ConfigFile, "none"),
			joinArgs(args),
		)
	}
}

// LogPipelineEnd writes the pipeline-end audit entry with the elapsed time.
func (e *Engine) LogPipelineEnd(elapsedSeconds int) {
	if e.state.Audit != nil {
		e.state.Audit.Logf("event=pipeline-end duration=%ds target=%s",
			elapsedSeconds, e.state.Cfg.Domain)
	}
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	if out == "" {
		return "(none)"
	}
	return out
}

// Logf is a convenience method that delegates to the state's logger so that
// phases can use e.Logf instead of e.state.Log.Infof.
func (e *Engine) Logf(format string, args ...any) {
	e.state.Log.Info(format, args...)
}

// Ensure logger is used so unused-import doesn't fire if logutil changes.
var _ = logutil.New
