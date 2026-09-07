// Package version holds build-time metadata injected via -ldflags.
package version

import (
	"fmt"
	"runtime"
)

// These variables are set at build time via:
//
//	go build -ldflags "-X metsuke/internal/version.Version=... -X metsuke/internal/version.GitCommit=..."
//
// When unset (e.g. `go run`), they fall back to "dev" / "unknown".
var (
	// Version is the semantic version of the metsuke binary.
	Version = "dev"
	// GitCommit is the short git commit hash the binary was built from.
	GitCommit = "unknown"
	// BuildDate is the ISO-8601 build timestamp (optional).
	BuildDate = "unknown"
)

// String returns a single-line version banner suitable for --version.
func String() string {
	return fmt.Sprintf("metsuke %s (commit %s, built %s, %s/%s)",
		Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
}
