package portscan

import (
	"os"
	"path/filepath"
	"strings"

	"metsuke/internal/pipeline"
)

// prepareTargets returns the path to the file listing port-scan targets.
// If --skip-cdn is set and httpx found CDN-fronted hosts, it writes a
// filtered list (non-CDN only) to ports/targets_noncdn.txt and returns that.
// Otherwise it falls back to subdomains/all_subdomains.txt.
//
// This mirrors the bash prepare_port_targets() function.
func prepareTargets(s *pipeline.State) string {
	defaultFile := filepath.Join(s.OutDir, "subdomains", "all_subdomains.txt")
	if !s.Cfg.SkipCDN {
		return defaultFile
	}
	httpxFull := filepath.Join(s.OutDir, "httpx", "httpx_full.json")
	if !pipeline.IsNonEmpty(httpxFull) {
		return defaultFile
	}

	data, err := os.ReadFile(httpxFull)
	if err != nil {
		return defaultFile
	}
	portsDir := filepath.Join(s.OutDir, "ports")
	_ = os.MkdirAll(portsDir, 0o700)
	noncdnPath := filepath.Join(portsDir, "targets_noncdn.txt")

	seen := make(map[string]struct{})
	var out []byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "\"cdn\":true") {
			continue
		}
		host := extractHost(line)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, []byte(host)...)
		out = append(out, '\n')
	}
	if len(out) == 0 {
		return defaultFile
	}
	if err := os.WriteFile(noncdnPath, out, 0o600); err != nil {
		return defaultFile
	}
	return noncdnPath
}

// extractHost extracts the hostname from a httpx JSON line, stripping the
// scheme and path. It looks for the "input", "host", or "url" field.
func extractHost(line string) string {
	for _, key := range []string{"\"input\":", "\"host\":", "\"url\":"} {
		if v := extractJSONValue(line, key); v != "" {
			return stripScheme(v)
		}
	}
	return ""
}

// extractJSONValue returns the string value following a JSON key marker.
func extractJSONValue(line, marker string) string {
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimLeft(line[idx+len(marker):], " \t")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	end := strings.Index(rest[1:], "\"")
	if end < 0 {
		return ""
	}
	return rest[1 : 1+end]
}

// stripScheme removes a leading http:// or https:// and any trailing path
// from a URL, returning just the host (with optional :port).
func stripScheme(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if idx := strings.Index(u, "/"); idx >= 0 {
		u = u[:idx]
	}
	return u
}
