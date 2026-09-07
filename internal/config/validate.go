package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Validate enforces every input invariant from the bash version's
// validate_inputs(). It returns an error describing the first violation.
// Call this only after CLI flags + config file + env vars have all been
// merged into c.
func (c *Config) Validate() error {
	c.Domain = strings.ToLower(strings.TrimSpace(c.Domain))
	if c.Domain == "" {
		return fmt.Errorf("domain is required (-d)")
	}
	if !domainRE.MatchString(c.Domain) {
		return fmt.Errorf("invalid or unsafe domain value: %q (must be a plain DNS name)", c.Domain)
	}

	if c.Threads < 1 || c.Threads > 500 {
		return fmt.Errorf("threads must be between 1 and 500 (got %d)", c.Threads)
	}
	if c.Timeout < 3 || c.Timeout > 300 {
		return fmt.Errorf("--timeout must be 3-300 seconds (got %d)", c.Timeout)
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("--rate-limit must be >= 0 (got %d)", c.RateLimit)
	}

	for _, tok := range strings.Split(c.NucleiSeverity, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if !severitySet[tok] {
			return fmt.Errorf("invalid --nuclei-severity value: %q (token %q not recognised)", c.NucleiSeverity, tok)
		}
	}

	if c.BurpPassive || c.BurpActiveScan {
		host, port, ok := splitHostPort(c.BurpProxy)
		if !ok || !burpProxyHostRE.MatchString(host) {
			return fmt.Errorf("invalid Burp proxy host: %q", host)
		}
		if !isNumeric(port) {
			return fmt.Errorf("invalid Burp proxy port: %q", port)
		}
	}
	if c.BurpActiveScan {
		if !burpAPIURLRE.MatchString(c.BurpAPIURL) {
			return fmt.Errorf("invalid --burp-api-url: %q", c.BurpAPIURL)
		}
	}

	if c.SessionHeaderFile != "" {
		if _, err := os.Stat(c.SessionHeaderFile); err != nil {
			return fmt.Errorf("--session-header-file not found: %s", c.SessionHeaderFile)
		}
		// Warn (not fatal) if the file is more permissive than 0600/0400.
		checkSecretFilePerms(c.SessionHeaderFile)
	}

	// --exclude-sub regexes must compile before we trust them in a filter.
	for _, rx := range c.ExcludeSubs {
		if _, err := regexp.Compile(rx); err != nil {
			return fmt.Errorf("invalid --exclude-sub regex %q: %w", rx, err)
		}
	}

	// JS secret scan tuning must be sane.
	if c.MaxJSFiles < 0 {
		return fmt.Errorf("--max-js-files must be >= 0 (got %d)", c.MaxJSFiles)
	}
	if c.JSConcurrency < 1 {
		return fmt.Errorf("--js-concurrency must be >= 1 (got %d)", c.JSConcurrency)
	}

	return nil
}
