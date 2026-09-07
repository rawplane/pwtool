package httpxprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"metsuke/internal/pipeline"
)

// buildArgs constructs the httpx command-line from the config.
func buildArgs(s *pipeline.State, in, out string) []string {
	args := []string{
		"-l", in,
		"-silent", "-threads", fmt.Sprintf("%d", s.Cfg.Threads),
		"-timeout", fmt.Sprintf("%d", s.Cfg.Timeout),
		"-retries", "2",
		"-status-code", "-title", "-tech-detect", "-content-length",
		"-follow-redirects", "-ip", "-cdn",
	}
	if s.Cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", s.Cfg.RateLimit))
	}
	if s.Cfg.BurpPassive {
		args = append(args, "-http-proxy", "http://"+s.Cfg.BurpProxy)
		s.Log.Burp("Traffic will be mirrored to Burp proxy %s → Site Map populated", s.Cfg.BurpProxy)
	}
	for _, h := range s.Headers {
		args = append(args, "-H", h)
	}
	args = append(args, "-json", "-o", filepath.Join(out, "httpx_full.json"))
	return args
}

// extractLiveHosts reads httpx_full.json (one JSON object per line) and
// extracts the "url" field for all live hosts and all CDN-fronted hosts,
// writing them to live_hosts.txt and cdn_hosts.txt respectively.
//
// We use a minimal JSON parser (extractField) rather than encoding/json
// because httpx writes one JSON object per line (JSONL), and we only need
// two fields — this avoids pulling in a full JSON dependency for the hot
// path. This mirrors the bash version's `jq -r '.url'` filter.
func extractLiveHosts(out string) error {
	fullPath := filepath.Join(out, "httpx_full.json")
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return err
	}
	var live, cdn []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		url := extractField(line, "\"url\":")
		if url == "" {
			continue
		}
		live = append(live, url)
		if extractField(line, "\"cdn\":true") != "" ||
			strings.Contains(line, "\"cdn\":true") {
			cdn = append(cdn, url)
		}
	}
	if err := writeLines(filepath.Join(out, "live_hosts.txt"), dedupSort(live)); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(out, "cdn_hosts.txt"), dedupSort(cdn)); err != nil {
		return err
	}
	return nil
}

// extractField returns the string value following a JSON key marker in a
// single-line JSON object. It handles the "key":"value" pattern by finding
// the first quote after the colon.
func extractField(line, marker string) string {
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(marker):]
	rest = strings.TrimLeft(rest, " \t")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	end := strings.Index(rest[1:], "\"")
	if end < 0 {
		return ""
	}
	return rest[1 : 1+end]
}

func dedupSort(lines []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	return out
}

func writeLines(path string, lines []string) error {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
