package urldiscovery

import (
	"os"
	"regexp"
	"sort"
	"strings"
)

// splitAndDedupe splits s on newlines, trims whitespace, deduplicates, and
// returns a sorted unique list. Mirrors `sort -u`.
func splitAndDedupe(s string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// writeLines writes lines (one per line) to path with mode 0600.
func writeLines(path string, lines []string) {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o600)
}

// filterLines returns lines matching the given regex pattern.
func filterLines(lines []string, pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, l := range lines {
		if re.MatchString(l) && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// normalizeDedupeFile reads URLs from inPath, applies NormalizeAndDedupe,
// and writes the result to outPath.
func normalizeDedupeFile(inPath, outPath string) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	return NormalizeAndDedupe(in, out)
}
