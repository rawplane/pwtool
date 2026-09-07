package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"metsuke/internal/pipeline"
	"metsuke/internal/version"
)

func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	reportDir := filepath.Join(s.OutDir, "report")
	if err := os.MkdirAll(reportDir, 0o700); err != nil {
		return err
	}

	subs := countLine(filepath.Join(s.OutDir, "subdomains", "all_subdomains.txt"))
	lives := countLine(filepath.Join(s.OutDir, "httpx", "live_hosts.txt"))
	cdns := countLine(filepath.Join(s.OutDir, "httpx", "cdn_hosts.txt"))
	raws := countLine(filepath.Join(s.OutDir, "urls", "all_urls_raw.txt"))
	urls := countLine(filepath.Join(s.OutDir, "urls", "all_urls.txt"))
	js := countLine(filepath.Join(s.OutDir, "urls", "js_files.txt"))
	secrets := countLine(filepath.Join(s.OutDir, "vulns", "js_secrets.txt"))
	sens := countLine(filepath.Join(s.OutDir, "urls", "extended_sensitive_endpoints.txt"))
	take := countLine(filepath.Join(s.OutDir, "vulns", "takeover_results.jsonl"))
	nuc := countLine(filepath.Join(s.OutDir, "vulns", "nuclei_results.jsonl"))

	elapsed := int(time.Since(s.Cfg.StartedAt).Seconds())
	startedStr := s.Cfg.StartedAt.Format(time.RFC3339)

	// summary.txt
	summary := fmt.Sprintf("\n\n \x76\xee\x32 (metsuke) — Recon Summary — %s\n", s.Cfg.Domain)
	summary = "\n\n 目付 (metsuke) — Recon Summary — " + s.Cfg.Domain + "\n"
	summary += fmt.Sprintf("Started           : %s\n", startedStr)
	summary += fmt.Sprintf("Duration          : %ds\n", elapsed)
	summary += fmt.Sprintf("Output            : %s\n", s.OutDir)
	summary += fmt.Sprintf("Subdomains        : %d\n", subs)
	summary += fmt.Sprintf("Live hosts        : %d (CDN/WAF: %d)\n", lives, cdns)
	summary += fmt.Sprintf("Raw URLs          : %d\n", raws)
	summary += fmt.Sprintf("Unique URLs       : %d\n", urls)
	summary += fmt.Sprintf("JS files          : %d\n", js)
	summary += fmt.Sprintf("JS secret candidates     : %d\n", secrets)
	summary += fmt.Sprintf("Sensitive endpoints      : %d\n", sens)
	summary += fmt.Sprintf("Takeover findings : %d\n", take)
	summary += fmt.Sprintf("Nuclei findings   : %d\n", nuc)

	summaryPath := filepath.Join(reportDir, "summary.txt")
	if err := os.WriteFile(summaryPath, []byte(summary), 0o600); err != nil {
		return err
	}
	fmt.Print(summary)

	// summary.json
	type Counts struct {
		Subdomains         int `json:"subdomains"`
		LiveHosts          int `json:"live_hosts"`
		CdnHosts           int `json:"cdn_hosts"`
		UniqueUrls         int `json:"unique_urls"`
		JsSecretCandidates int `json:"js_secret_candidates"`
		SensitiveEndpoints int `json:"sensitive_endpoints"`
		TakeoverFindings   int `json:"takeover_findings"`
		NucleiFindings     int `json:"nuclei_findings"`
	}
	type SummaryJSON struct {
		Domain           string `json:"domain"`
		Version          string `json:"version"`
		StartedAt        string `json:"started_at"`
		DurationSeconds  int    `json:"duration_seconds"`
		OutputDir        string `json:"output_dir"`
		Counts           Counts `json:"counts"`
	}

	sj := SummaryJSON{
		Domain:          s.Cfg.Domain,
		Version:         version.Version,
		StartedAt:       startedStr,
		DurationSeconds: elapsed,
		OutputDir:       s.OutDir,
		Counts: Counts{
			Subdomains:         subs,
			LiveHosts:          lives,
			CdnHosts:           cdns,
			UniqueUrls:         urls,
			JsSecretCandidates: secrets,
			SensitiveEndpoints: sens,
			TakeoverFindings:   take,
			NucleiFindings:     nuc,
		},
	}
	data, err := json.MarshalIndent(sj, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(reportDir, "summary.json"), data, 0o600); err != nil {
		return err
	}

	s.Log.OK("Done. All results saved to: %s (summary.txt / summary.json)", s.OutDir)
	if s.Notifier != nil {
		s.Notifier.Send(ctx, fmt.Sprintf("metsuke finished: %s in %ds — subdomains=%d live=%d nuclei=%d takeover=%d",
			s.Cfg.Domain, elapsed, subs, lives, nuc, take))
	}
	return nil
}
