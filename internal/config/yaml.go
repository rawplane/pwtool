package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadYAMLFile loads a simple YAML-like config file and applies its keys to
// c. Only the subset of YAML used by metsuke config files is supported:
//
//	key: value          # scalar
//	key:
//	  - item1           # list (for session-headers / exclude-sub)
//	  - item2
//
// Comments (lines starting with '#') and blank lines are ignored. This is a
// deliberately minimal parser — it avoids pulling in a heavy YAML dependency
// (and its transitive deps) for what is essentially a flat key/value file.
func LoadYAMLFile(c *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	return parseYAML(c, string(data))
}

// parseYAML updates c from the contents of a minimal YAML document.
func parseYAML(c *Config, src string) error {
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		raw := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Strip inline comments.
		if idx := strings.Index(trimmed, " #"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}

		// List item under a previous key.
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			continue // handled by the parent key block below
		}

		colon := strings.Index(trimmed, ":")
		if colon < 0 {
			continue // not a key: value line
		}
		key := strings.TrimSpace(trimmed[:colon])
		val := strings.TrimSpace(trimmed[colon+1:])

		// If val is empty, this may be a list block — collect following
		// "  - item" lines.
		if val == "" {
			items := collectListItems(lines, i+1)
			if len(items) > 0 {
				applyList(c, key, items)
				i += len(items) // skip the items we consumed
			}
			continue
		}

		// Strip surrounding quotes from scalar values.
		val = unquote(val)
		applyScalar(c, key, val)
	}
	return nil
}

// collectListItems reads consecutive "  - item" lines starting at lineIdx,
// returning the item values (without the dash).
func collectListItems(lines []string, lineIdx int) []string {
	var items []string
	for j := lineIdx; j < len(lines); j++ {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "- ") && trimmed != "-" {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		items = append(items, unquote(item))
	}
	return items
}

// applyScalar sets a single key/value on c.
func applyScalar(c *Config, key, val string) {
	switch strings.ToLower(key) {
	case "threads":
		if n, err := strconv.Atoi(val); err == nil {
			c.Threads = n
		}
	case "timeout", "http_timeout":
		if n, err := strconv.Atoi(val); err == nil {
			c.Timeout = n
		}
	case "rate_limit":
		if n, err := strconv.Atoi(val); err == nil {
			c.RateLimit = n
		}
	case "nuclei_severity":
		c.NucleiSeverity = val
	case "nuclei_tags":
		c.NucleiTags = val
	case "webhook_url":
		c.WebhookURL = val
	case "max_js_files":
		if n, err := strconv.Atoi(val); err == nil {
			c.MaxJSFiles = n
		}
	case "js_concurrency":
		if n, err := strconv.Atoi(val); err == nil {
			c.JSConcurrency = n
		}
	case "burp_proxy":
		c.BurpProxy = val
	case "burp_api_url":
		c.BurpAPIURL = val
	case "burp_api_key":
		c.BurpAPIKey = val
	}
}

// applyList sets a list-valued key on c.
func applyList(c *Config, key string, items []string) {
	switch strings.ToLower(key) {
	case "session_headers":
		c.SessionHeaders = append(c.SessionHeaders, items...)
	case "exclude_subs", "exclude_sub":
		c.ExcludeSubs = append(c.ExcludeSubs, items...)
	}
}

// unquote strips a single layer of surrounding single or double quotes.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
