package subdomain

import (
	"os"
	"strings"
)

// splitLines splits a string on newlines, returning non-empty trimmed lines.
// crt.sh name_value can contain multiple newline-separated hosts.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// writeFile writes data to path with mode 0600, creating parent dirs.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
