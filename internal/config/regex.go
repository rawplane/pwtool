package config

import "regexp"

// domainRE matches a plain DNS hostname: labels of [a-z0-9-], joined by
// dots, TLD of 2-63 alpha chars. Anchored so that
// "evil.example.net.attacker.io" does NOT match "example.net".
var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// burpProxyHostRE restricts the Burp proxy host to a safe charset before it
// is used in a dialer. Pure hostnames or IPs only — no userinfo or path.
var burpProxyHostRE = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

// burpAPIURLRE restricts the Burp REST API URL to an http(s) URL with a
// safe charset, preventing injection of unexpected schemes or path traversal.
var burpAPIURLRE = regexp.MustCompile(`^https?://[a-zA-Z0-9.:/-]+$`)

// severitySet is the set of accepted nuclei severity tokens.
var severitySet = map[string]bool{
	"info": true, "low": true, "medium": true,
	"high": true, "critical": true, "unknown": true,
}
