package burp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"metsuke/internal/pipeline"
)

func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	if !s.Cfg.BurpActiveScan {
		return nil
	}
	if s.Cfg.PassiveOnly {
		s.Log.Info("passive-only mode: Burp active scan skipped")
		return nil
	}
	if s.Cfg.BurpAPIKey == "" {
		s.Log.Warn("BURP_API_KEY is not set, skipping active scan trigger.")
		return nil
	}

	live := filepath.Join(s.OutDir, "httpx", "live_hosts.txt")
	if !pipeline.IsNonEmpty(live) {
		s.Log.Warn("No live hosts to send to Burp, skipping.")
		return nil
	}

	reportDir := filepath.Join(s.OutDir, "report")
	if err := os.MkdirAll(reportDir, 0o700); err != nil {
		return err
	}
	out := filepath.Join(reportDir, "burp_scan_response.json")

	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] POST %s/<REDACTED_KEY>/v0.1/scan with %d URLs",
			s.Cfg.BurpAPIURL, pipeline.CountLines(live))
		return nil
	}

	s.Log.Burp("Sending %d URLs to the Burp Suite REST API for active scan...",
		pipeline.CountLines(live))
	s.Log.Warn("REST API endpoint format may vary between Burp versions — check %s/swagger.json if this fails.",
		strings.TrimRight(s.Cfg.BurpAPIURL, "/"))

	urls, err := readLines(live)
	if err != nil {
		return err
	}

	endpoint := strings.TrimRight(s.Cfg.BurpAPIURL, "/") + "/" + s.Cfg.BurpAPIKey + "/v0.1/scan"
	payload, err := json.Marshal(map[string][]string{"urls": urls})
	if err != nil {
		return fmt.Errorf("marshal burp payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = sendToBurp(ctx, endpoint, payload, out)
		if err == nil {
			s.Log.OK("Active scan successfully triggered. Response saved to %s", out)
			if s.Notifier != nil {
				s.Notifier.Send(ctx, fmt.Sprintf("🎯 Burp active scan triggered for %s", s.Cfg.Domain))
			}
			return nil
		}
		lastErr = err
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.Log.Err("Failed to trigger active scan after several attempts (check API URL/key): %v", lastErr)
	return nil
}

func sendToBurp(ctx context.Context, endpoint string, payload []byte, outPath string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body := bytes.NewBuffer(nil)
	_, _ = body.ReadFrom(resp.Body)
	_ = os.WriteFile(outPath, body.Bytes(), 0o600)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("burp API returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
