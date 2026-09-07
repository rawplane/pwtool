package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"metsuke/internal/audit"
	"metsuke/internal/authgate"
	"metsuke/internal/config"
	"metsuke/internal/executil"
	"metsuke/internal/logutil"
	"metsuke/internal/notify"
	burp "metsuke/internal/phases/09_burp"
	httpxprobe "metsuke/internal/phases/02_httpx"
	nuclei "metsuke/internal/phases/08_nuclei"
	portscan "metsuke/internal/phases/03_portscan"
	report "metsuke/internal/phases/10_report"
	screenshots "metsuke/internal/phases/07_screenshots"
	secretscan "metsuke/internal/phases/05_secretscan"
	subdomain "metsuke/internal/phases/01_subdomain"
	takeover "metsuke/internal/phases/06_takeover"
	urldiscovery "metsuke/internal/phases/04_urldiscovery"
	"metsuke/internal/pipeline"
)

func execute(cfg *config.Config, rawArgs []string) error {
	if err := setupWorkspace(cfg); err != nil {
		return err
	}
	defer func() {
		if cfgLock != nil {
			cfgLock.Release()
		}
	}()

	logger := logutil.New(os.Stdout, cfg.JsonLog)
	auditLog, err := audit.New(cfg.OutDir + "/audit.log")
	if err != nil {
		return err
	}
	defer auditLog.Close()

	runner := executil.NewRunner(logger.Info)
	runner.DryRun = cfg.DryRun

	notifier := notify.New(cfg.WebhookURL, !cfg.NoNotify)

	headers := buildSessionHeaders(cfg)

	state := pipeline.NewState(cfg, logger, auditLog, runner, notifier, cfg.OutDir)
	state.Headers = headers

	// Authorization gate (skipped in dry-run).
	if err := authgate.Confirm(authgate.Options{
		Domain:            cfg.Domain,
		DryRun:            cfg.DryRun,
		PassiveOnly:       cfg.PassiveOnly,
		ExtendedWorkflows: cfg.ExtendedWorkflows,
		BurpActiveScan:    cfg.BurpActiveScan,
	}, os.Stdin, os.Stdout, auditLog); err != nil {
		return err
	}

	// Signal handling: SIGINT/SIGTERM → cancel context, kill child process
	// groups, write audit log "interrupted", exit 130.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Warn("Interrupt received (%v) — stopping child processes and cleaning up...", sig)
		auditLog.Log("event=interrupted")
		cancel()
		os.Exit(130)
	}()

	engine := pipeline.NewEngine(state)

	// Audit pipeline start.
	redacted := audit.RedactArgs(rawArgs)
	engine.LogPipelineStart(redacted)

	// Construct phases.
	phSub := subdomain.New(runner, auditLog)
	phHttpx := httpxprobe.New(runner, auditLog)
	phPort := portscan.New(runner, auditLog)
	phURL := urldiscovery.New(runner, auditLog)
	phSecret := secretscan.New(runner, auditLog)
	phTakeover := takeover.New(runner, auditLog)
	phScreenshots := screenshots.New(runner, auditLog)
	phNuclei := nuclei.New(runner, auditLog)
	phBurp := burp.New(runner, auditLog)
	phReport := report.New()

	// Phase 1-2 always sequential.
	phases12 := []pipeline.Phase{phSub, phHttpx}
	if err := engine.RunSequential(ctx, phases12); err != nil {
		logger.Warn("early phases error: %v", err)
	}

	// Phase 3-4: sequential or parallel.
	if cfg.Parallel {
		if err := engine.RunParallel(ctx, phPort, phURL); err != nil {
			logger.Warn("parallel phase error: %v", err)
		}
	} else {
		if err := engine.RunSequential(ctx, []pipeline.Phase{phPort, phURL}); err != nil {
			logger.Warn("phase 3-4 error: %v", err)
		}
	}

	// Phases 5-10.
	rest := []pipeline.Phase{
		phSecret, phTakeover, phScreenshots, phNuclei, phBurp, phReport,
	}
	if err := engine.RunSequential(ctx, rest); err != nil {
		logger.Warn("later phases error: %v", err)
	}

	elapsed := int(time.Since(cfg.StartedAt).Seconds())
	engine.LogPipelineEnd(elapsed)
	return nil
}

// time is imported via the alias below to avoid a separate import block.
var _ = fmt.Sprintf
