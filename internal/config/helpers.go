package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// splitHostPort splits a "host:port" string. Unlike net.SplitHostPort, this
// only accepts a single colon — IPv6 brackets are not supported because the
// bash version's bash parameter expansion (${ARG_VALUE%%:*}) does not either.
func splitHostPort(s string) (host, port string, ok bool) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 || idx == len(s)-1 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

// isNumeric returns true if s consists only of ASCII digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// checkSecretFilePerms emits a warning (via stderr) if a file holding secrets
// is more permissive than 0600/0400. This mirrors the bash version's stat
// check on --session-header-file. It is advisory — it does not refuse to run.
func checkSecretFilePerms(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := info.Mode().Perm()
	if perm != 0o600 && perm != 0o400 {
		fmt.Fprintf(os.Stderr,
			"[WARN] Session header file permissions are %o — recommend chmod 600\n",
			perm)
	}
}

// ApplyDefaults populates any zero-valued field with its built-in default.
// This is called after the YAML config is loaded but before CLI flags are
// applied, so that CLI flags always win (v4 behaviour, not v3).
func (c *Config) ApplyDefaults() {
	if c.Threads == 0 {
		c.Threads = DefaultThreads
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.NucleiSeverity == "" {
		c.NucleiSeverity = DefaultNucleiSeverity
	}
	if c.MaxJSFiles == 0 {
		c.MaxJSFiles = DefaultMaxJSFiles
	}
	if c.JSConcurrency == 0 {
		c.JSConcurrency = DefaultJSConcurrency
	}
	if c.BurpProxy == "" {
		c.BurpProxy = DefaultBurpProxyHost + ":" + DefaultBurpProxyPort
	}
	if c.BurpAPIURL == "" {
		c.BurpAPIURL = DefaultBurpAPIURL
	}
	if c.WebhookURL == "" {
		c.WebhookURL = os.Getenv("RECON_WEBHOOK_URL")
	}
	if c.BurpAPIKey == "" {
		c.BurpAPIKey = os.Getenv("BURP_API_KEY")
	}
}

// countLines returns the number of non-empty lines in s, trimming a trailing
// newline so that a well-formed file does not report a phantom empty line.
func countLines(s string) int {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// itoa is a thin wrapper to avoid importing strconv in callers that only need
// int->string conversion for logging.
func itoa(n int) string {
	return strconv.Itoa(n)
}
