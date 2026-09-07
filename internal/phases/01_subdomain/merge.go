package subdomain

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"metsuke/internal/pipeline"
)

// mergeAndFilter reads all *.txt files in outDir, lowercases, strips
// wildcards and trailing dots, filters against the anchored scope regex,
// applies --exclude-sub patterns, and writes the deduplicated result.
func (p *Phase) mergeAndFilter(outDir, allOut string, s *pipeline.State) error {
	domain := s.Cfg.Domain
	seen := make(map[string]struct{})

	entries, err := os.ReadDir(outDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			h := normalizeHost(line)
			if h == "" {
				continue
			}
			if !InScope(h, domain) {
				continue
			}
			if excluded(h, s.Cfg.ExcludeSubs) {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
		}
	}

	// Sort for deterministic output.
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var b strings.Builder
	for _, h := range hosts {
		b.WriteString(h)
		b.WriteByte('\n')
	}
	return os.WriteFile(allOut, []byte(b.String()), 0o600)
}

// excluded returns true if host matches any --exclude-sub regex.
func excluded(host string, patterns []string) bool {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(host) {
			return true
		}
	}
	return false
}
