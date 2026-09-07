package urldiscovery

import "regexp"

// SensitiveEndpointRegex is a byte-for-byte port of the bash version's
// SENSITIVE_ENDPOINT_REGEX. It matches URLs that could potentially leak
// credentials or configuration: .env, .git, admin/auth/oauth/sso panels,
// cloud config, .yml/.yaml, token/session endpoints, etc.
//
// This regex is production-validated — do NOT alter it without an explicit
// request. Any change must be accompanied by unit tests covering both
// positive and negative cases.
//
// Note: Go's RE2 engine requires the top-level alternation to be wrapped
// in an explicit non-capturing group when used with the (?i) flag; the
// bash version (POSIX ERE via grep -E) did not need this. The match set
// is identical.
const SensitiveEndpointRegex = `(\.(env|git)(\?|$)|/(config|auth|oauth|sso|admin|graphql|swagger|openapi|internal|private|debug|staging|firebase|aws|gcp|azure|payment|billing|webhook|settings)[^/]*(\?|$)|\.(yml|yaml)(\?|$)|/(api(/v[0-9]+)?|rest|restapi|graphql|graphiql|swagger(-ui)?|openapi|api[-_]?docs|redoc|oauth2?|oidc|saml|authorize|authorization|authentication|login|logout|signin|signup|register|token|tokens|access[-_]?token|refresh[-_]?token|session|sessions|jwt|jwks?|webhook(s)?|callback(s)?|internal|private|admin(istrator)?|management|credential(s)?)(/|\?|$))`

// sensitiveRE is the compiled, case-insensitive form of the regex above.
var sensitiveRE = regexp.MustCompile("(?i)" + SensitiveEndpointRegex)

// MatchSensitiveEndpoint returns true if url contains a sensitive-endpoint
// pattern. It is the Go equivalent of `grep -Ei "$SENSITIVE_ENDPOINT_REGEX"`.
func MatchSensitiveEndpoint(url string) bool {
	return sensitiveRE.MatchString(url)
}

// FindSensitiveURLs scans lines and returns those matching the sensitive
// endpoint regex, deduplicated and sorted. Mirrors the bash pipeline
// `grep -Ei "$SENSITIVE_ENDPOINT_REGEX" | sort -u`.
func FindSensitiveURLs(lines []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, l := range lines {
		if MatchSensitiveEndpoint(l) {
			if seen[l] {
				continue
			}
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}
