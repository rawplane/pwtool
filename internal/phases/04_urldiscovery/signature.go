package urldiscovery

import (
	"sort"
	"strings"
)

// signature computes the dedup signature for a URL: the path with every
// segment templated, followed by the sorted, deduplicated list of query
// parameter names joined by "&".
//
// This is exactly the same algorithm as the awk version: split the path on
// "/", template each segment, split the query on "&", take the parameter
// name (before "="), deduplicate while preserving order, then sort
// alphabetically.
func signature(url string) string {
	queryIdx := strings.Index(url, "?")
	path := url
	query := ""
	if queryIdx >= 0 {
		path = url[:queryIdx]
		query = url[queryIdx+1:]
	}

	// Template each path segment.
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = templateSegment(s)
	}
	sig := strings.Join(segs, "/")

	if query != "" {
		var ordered []string
		seen := make(map[string]bool)
		for _, p := range strings.Split(query, "&") {
			kv := strings.SplitN(p, "=", 2)
			k := kv[0]
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
		for _, k := range ordered {
			sig = sig + "&" + k
		}
	}
	return sig
}
