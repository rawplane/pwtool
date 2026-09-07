package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"metsuke/internal/config"
	"metsuke/internal/lock"
)

// setupWorkspace creates the output directory tree (mode 0700), writes
// scope.txt, stores CLI session headers in a mode-0600 file, and acquires
// the single-instance lock.
func setupWorkspace(cfg *config.Config) error {
	if cfg.OutDir == "" {
		cfg.OutDir = fmt.Sprintf("./recon_%s_%s",
			cfg.Domain, cfg.StartedAt.Format("20060102_150405"))
	}

	for _, sub := range []string{"subdomains", "httpx", "ports", "urls", "screenshots", "vulns", "report"} {
		if err := os.MkdirAll(filepath.Join(cfg.OutDir, sub), 0o700); err != nil {
			return fmt.Errorf("create output dir %s: %w", sub, err)
		}
	}

	if err := os.WriteFile(filepath.Join(cfg.OutDir, "scope.txt"),
		[]byte(cfg.Domain+"\n"), 0o600); err != nil {
		return err
	}

	if len(cfg.SessionHeaders) > 0 {
		internalPath := filepath.Join(cfg.OutDir, ".session_headers.txt")
		data := strings.Join(cfg.SessionHeaders, "\n") + "\n"
		if err := os.WriteFile(internalPath, []byte(data), 0o600); err != nil {
			return err
		}
		_ = syscall.Chmod(internalPath, 0o600)
	}

	lk, err := lock.Acquire(cfg.OutDir)
	if err != nil {
		return err
	}
	cfgLock = lk
	return nil
}

var cfgLock *lock.Lock

// buildSessionHeaders merges CLI headers and --session-header-file into a
// single list, mirroring the bash build_header_args().
func buildSessionHeaders(cfg *config.Config) []string {
	var headers []string
	headers = append(headers, cfg.SessionHeaders...)
	if cfg.SessionHeaderFile != "" {
		data, err := os.ReadFile(cfg.SessionHeaderFile)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					headers = append(headers, line)
				}
			}
		}
	}
	return headers
}
