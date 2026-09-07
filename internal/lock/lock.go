// Package lock provides a single-instance lock for a metsuke output
// directory, replacing the bash version's mkdir-based .lock directory with
// an OS-level advisory file lock plus a PID file for stale-lock detection.
package lock

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Lock represents an acquired single-instance lock on a directory.
// Release must be called when the pipeline is done (usually via defer).
type Lock struct {
	f    *os.File
	path string
}

// Acquire tries to obtain an exclusive lock on <dir>/.lock.
//
// Stale-lock handling mirrors the bash behaviour:
//   - If the lock file exists and the PID inside it is still alive, abort.
//   - If the PID is no longer running, treat the lock as stale, remove it,
//     and acquire a fresh one.
//
// The advisory (flock) lock provides a second layer of protection: even if
// the PID file is missing or corrupted, a still-running metsuke process
// holding the flock will prevent a second instance from acquiring it.
func Acquire(dir string) (*Lock, error) {
	path := dir + "/.lock"
	// Ensure the directory exists before we try to lock a file inside it.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}

	// Check for a stale lock from a previous run.
	if pidStr, err := os.ReadFile(path); err == nil {
		pidStr := strings.TrimSpace(string(pidStr))
		if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
			if alive(pid) {
				return nil, fmt.Errorf("another metsuke instance (PID %d) is running on this output directory", pid)
			}
		}
		// PID not alive → stale lock, remove it.
		_ = os.Remove(path)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	// Non-blocking exclusive flock. If another live process holds it (even
	// without a valid PID file), this fails immediately.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("output directory is locked by another metsuke instance: %w", err)
	}

	// Write our PID for future stale-lock detection.
	pidStr := fmt.Sprintf("%d\n", os.Getpid())
	if _, err := f.WriteString(pidStr); err != nil {
		// Best-effort: the flock is the authoritative guard.
		_ = err
	}

	return &Lock{f: f, path: path}, nil
}

// Release drops the exclusive lock and removes the lock file. It is safe to
// call on a nil or already-released Lock.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	// Release the advisory flock first, then close, then remove the PID file.
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	_ = os.Remove(l.path)
}

// alive reports whether a process with the given PID is currently running.
func alive(pid int) bool {
	// Sending signal 0 to a process is the POSIX way to test for liveness
	// without actually signalling it.
	if err := syscall.Kill(pid, 0); err == nil {
		return true
	}
	// ESRCH means "no such process" → not alive. EPERM means the process
	// exists but we don't have permission to signal it → treat as alive.
	return false
}
