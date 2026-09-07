package secretscan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

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

func (p *Phase) Name() string { return "Phase 5: JS Hardcoded-Secret Detection" }

func (p *Phase) ShouldSkip(s *pipeline.State) bool {
	if !s.Cfg.ExtendedWorkflows || s.Cfg.PassiveOnly {
		return true
	}
	if !s.Cfg.Resume {
		return false
	}
	out := filepath.Join(s.OutDir, "vulns", "js_secrets.txt")
	return pipeline.IsNonEmpty(out)
}

func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	in := filepath.Join(s.OutDir, "urls", "js_files.txt")
	vulnsDir := filepath.Join(s.OutDir, "vulns")
	if err := os.MkdirAll(vulnsDir, 0o700); err != nil {
		return err
	}
	out := filepath.Join(vulnsDir, "js_secrets.txt")

	if !pipeline.IsNonEmpty(in) {
		s.Log.Info("No JS files collected, skipping.")
		return nil
	}

	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] fetch <= %d JS files (concurrency %d) -> scan secret patterns -> %s",
			s.Cfg.MaxJSFiles, s.Cfg.JSConcurrency, out)
		return nil
	}

	s.Log.Ext("Fetching JS files and scanning for hardcoded credential patterns (passive GETs)...")

	urls, err := readLinesLimit(in, s.Cfg.MaxJSFiles)
	if err != nil {
		return err
	}

	outFile, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var mu sync.Mutex
	var totalFindings int

	jobs := make(chan string, len(urls))
	for _, u := range urls {
		jobs <- u
	}
	close(jobs)

	concurrency := s.Cfg.JSConcurrency
	if concurrency < 1 {
		concurrency = 10
	}
	if concurrency > len(urls) && len(urls) > 0 {
		concurrency = len(urls)
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jsURL := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				secrets := fetchAndScan(ctx, client, jsURL)
				if len(secrets) > 0 {
					mu.Lock()
					for _, sec := range secrets {
						fmt.Fprintf(outFile, "%s\t%s\n", jsURL, sec)
						totalFindings++
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if totalFindings > 0 {
		s.Log.Warn("%d hardcoded secret candidate(s) -> %s (verify manually — patterns only)", totalFindings, out)
		if s.Notifier != nil {
			s.Notifier.Send(ctx, fmt.Sprintf("🔑 %d JS secret candidate(s) on %s", totalFindings, s.Cfg.Domain))
		}
	} else {
		s.Log.OK("No hardcoded secret candidates found in sampled JS files")
	}

	return nil
}

func readLinesLimit(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
			if limit > 0 && len(lines) >= limit {
				break
			}
		}
	}
	return lines, scanner.Err()
}

func fetchAndScan(ctx context.Context, client *http.Client, targetURL string) []string {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Limit read to 5MB (like bash --max-filesize 5000000)
	lr := io.LimitReader(resp.Body, 5*1024*1024)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		return nil
	}

	return FindSecrets(string(bodyBytes))
}
