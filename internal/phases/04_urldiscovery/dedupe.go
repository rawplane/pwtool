package urldiscovery

import (
	"bufio"
	"io"
	"sort"
	"strings"
)

// NormalizeAndDedupe reads URLs from in (one per line), deduplicates them by
// their signature (templated path + sorted param names), and writes the
// ORIGINAL URL (not the templated one) of each unique signature to out —
// exactly like the awk version's `if (!seen[sig]++) { print }`.
//
// A final `sort -u` is applied to the output, matching the bash pipeline
// `awk ... | sort -u`.
func NormalizeAndDedupe(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	seen := make(map[string]bool)
	var urls []string
	for scanner.Scan() {
		url := scanner.Text()
		url = strings.TrimRight(url, "\r")
		if url == "" {
			continue
		}
		sig := signature(url)
		if seen[sig] {
			continue
		}
		seen[sig] = true
		urls = append(urls, url)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// sort -u
	sort.Strings(urls)
	seen2 := make(map[string]bool)
	for _, u := range urls {
		if seen2[u] {
			continue
		}
		seen2[u] = true
		io.WriteString(out, u+"\n")
	}
	return nil
}
