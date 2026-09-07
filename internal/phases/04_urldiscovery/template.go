// Package urldiscovery implements Phase 4: URL & endpoint discovery.
package urldiscovery

import "regexp"

// uuidRE matches a full UUID: 8-4-4-4-12 hex digits.
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// hexLongRE matches a hex string of 24+ chars (e.g. MongoDB ObjectIds).
var hexLongRE = regexp.MustCompile(`^[0-9a-fA-F]{24,}$`)

// alnumMixedRE matches an alphanumeric string (incl. _ and -) of length >=14
// that contains BOTH a letter and a digit.
var alnumMixedRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var hasLetterRE = regexp.MustCompile(`[A-Za-z]`)
var hasDigitRE = regexp.MustCompile(`[0-9]`)

// numericRE matches a pure-numeric segment.
var numericRE = regexp.MustCompile(`^[0-9]+$`)

// templateSegment applies the same path-segment templating rules as the
// awk version: UUID -> :uuid, hex>=24 -> :rid, alnum mixed >=14 -> :rid,
// numeric -> :id.
func templateSegment(seg string) string {
	if uuidRE.MatchString(seg) {
		return ":uuid"
	}
	if hexLongRE.MatchString(seg) {
		return ":rid"
	}
	if len(seg) >= 14 && alnumMixedRE.MatchString(seg) &&
		hasLetterRE.MatchString(seg) && hasDigitRE.MatchString(seg) {
		return ":rid"
	}
	if numericRE.MatchString(seg) {
		return ":id"
	}
	return seg
}
