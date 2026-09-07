// Package audit implements an append-only, timestamped audit trail with
// automatic secret redaction. The audit log is a core safety mechanism of
// metsuke: it records every significant lifecycle event (authorization,
// pipeline start/end, interruptions) with secrets stripped so the log file
// itself is never a credential leak vector.
package audit

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// SecretFlags is the set of CLI flags whose following value must be redacted
// in any recorded argument list. Mirrors the bash redact_args() behaviour.
var SecretFlags = []string{
	"--session-header",
	"--burp-api-key",
}

// Logger writes timestamped audit lines to an append-only file and to stderr.
// The stderr stream is colourised (magenta [AUDIT] prefix) so operators can
// follow the trail live during a run.
//
// All writes are serialised by a mutex so concurrent phases (in --parallel
// mode) cannot interleave a single line.
type Logger struct {
	mu  sync.Mutex
	f   *os.File
	err io.Writer
}

// New opens (or creates) the audit file at path for append-only writes.
// If path is empty, no file is written — only the stderr mirror is kept.
func New(path string) (*Logger, error) {
	l := &Logger{err: os.Stderr}
	if path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		l.f = f
	}
	return l, nil
}

// Close flushes and closes the underlying audit file. Safe to call on a
// Logger with no file.
func (l *Logger) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}

// Log writes a single audit event of the form:
//
//	[2006-01-02T15:04:05Z07:00] event=<message>
//
// to both the audit file and stderr. Failures writing to the file are
// silently ignored (best-effort, like the bash version) so that a full disk
// cannot abort a running pipeline.
func (l *Logger) Log(message string) {
	if l == nil {
		return
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format(time.RFC3339), message)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_, _ = l.f.WriteString(line)
	}
	if l.err != nil {
		// stderr mirror with magenta [AUDIT] prefix
		fmt.Fprintf(l.err, "\033[0;35m[AUDIT]\033[0m %s", message)
		if !strings.HasSuffix(message, "\n") {
			fmt.Fprint(l.err, "\n")
		}
	}
}

// Logf is a printf-style convenience wrapper for Log.
func (l *Logger) Logf(format string, args ...any) {
	l.Log(fmt.Sprintf(format, args...))
}

// RedactArgs rebuilds a CLI argument slice with the value following any
// SecretFlags replaced by the literal string "REDACTED". This mirrors the
// bash redact_args() helper and is used for the pipeline-start audit entry.
func RedactArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, 0, len(args))
	secretSet := make(map[string]struct{}, len(SecretFlags))
	for _, f := range SecretFlags {
		secretSet[f] = struct{}{}
	}
	prev := ""
	for _, a := range args {
		if _, secret := secretSet[prev]; secret {
			out = append(out, "REDACTED")
		} else {
			out = append(out, a)
		}
		prev = a
	}
	return out
}

// JoinArgs joins an argument slice into a single space-separated string for
// logging. Quoting is deliberately minimal (the audit log is for human
// inspection, not for re-execution).
func JoinArgs(args []string) string {
	return strings.Join(args, " ")
}
