// Package executil provides a robust command runner with process-group
// isolation, context-aware cancellation, and optional dry-run logging.
//
// All child processes are spawned in their own process group (Setpgid) so
// that a single signal sent to the group reliably kills the whole process
// tree — mirroring the bash version's `kill $(jobs -p)` interrupt handler.
package executil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// ErrDryRun is returned by Run when dry-run mode is enabled, signalling the
// caller that the command was only logged, not executed.
var ErrDryRun = errors.New("dry-run: command not executed")

// Runner executes external commands with optional timeout, dry-run, and
// output redirection. The zero value is NOT ready to use — use NewRunner.
type Runner struct {
	// DryRun, when true, causes Run to log the command via the Log func and
	// return ErrDryRun without spawning any process.
	DryRun bool

	// Log is called with the human-readable command representation. It is
	// used both for normal logging and for dry-run messages.
	Log func(format string, args ...any)

	// Stdout / Stderr, when nil, inherit the parent's streams.
	Stdout io.Writer
	Stderr io.Writer
}

// NewRunner returns a Runner that logs via the provided logger and inherits
// the parent process stdout/stderr.
func NewRunner(log func(format string, args ...any)) *Runner {
	return &Runner{
		Log:    log,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

// Cmd represents a prepared command to be run by Runner.Run.
type Cmd struct {
	// Name is the executable name (looked up via PATH).
	Name string
	// Args are the command arguments (flags + values).
	Args []string
	// Stdin, when non-empty, is piped to the child's stdin.
	Stdin string
	// Dir is the working directory; empty means inherit.
	Dir string
	// Env, when non-nil, replaces the child environment.
	Env []string
}

// Run executes the command under ctx. If r.DryRun is set, the command is
// logged (prefixed "[DRY-RUN]") and ErrDryRun is returned. On signal/context
// cancellation the entire child process group is killed.
//
// The command is always spawned with Setpgid=true so that we can later send
// a signal to the group PID and reliably tear down grandchildren.
func (r *Runner) Run(ctx context.Context, cmd Cmd) error {
	preview := formatCommand(cmd.Name, cmd.Args)
	if r.DryRun {
		if r.Log != nil {
			r.Log("[DRY-RUN] %s", preview)
		}
		return ErrDryRun
	}
	if r.Log != nil {
		r.Log("running: %s", preview)
	}

	c := exec.CommandContext(ctx, cmd.Name, cmd.Args...)
	// Spawn the child in its own process group so we can later signal the
	// whole tree (child + grandchildren) reliably on interrupt.
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Dir = cmd.Dir
	if cmd.Env != nil {
		c.Env = cmd.Env
	}
	c.Stdout = r.Stdout
	c.Stderr = r.Stderr
	if cmd.Stdin != "" {
		c.Stdin = stringReader(cmd.Stdin)
	}
	if err := c.Start(); err != nil {
		return fmt.Errorf("%s: %w", cmd.Name, err)
	}

	// Ensure the whole process group is killed if the context is cancelled
	// (e.g. SIGINT). exec.CommandContext already sends SIGKILL to the child
	// on cancellation, but only to the direct child — not grandchildren that
	// the child may have spawned. Kill the group to be safe.
	stop := context.AfterFunc(ctx, func() {
		if c.Process != nil {
			// SIGTERM the whole group first, then SIGKILL if it lingers.
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGTERM)
			time.Sleep(500 * time.Millisecond)
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
	})
	defer stop()

	if err := c.Wait(); err != nil {
		return fmt.Errorf("%s: %w", cmd.Name, err)
	}
	return nil
}

// RunWithTimeout is a convenience wrapper that runs the command under a
// context with the given timeout. A zero timeout means no deadline.
func (r *Runner) RunWithTimeout(timeout time.Duration, cmd Cmd) error {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return r.Run(ctx, cmd)
}

// CheckInstalled returns true if the named executable is found on PATH.
func CheckInstalled(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// formatCommand returns a single-line shell-like representation of a command.
func formatCommand(name string, args []string) string {
	out := name
	for _, a := range args {
		out += " " + shellQuote(a)
	}
	return out
}

// shellQuote wraps a in double quotes if it contains spaces or shell
// metacharacters; otherwise returns it as-is.
func shellQuote(a string) string {
	if a == "" {
		return `""`
	}
	for _, r := range a {
		if r == ' ' || r == '\t' || r == '\'' || r == '"' || r == '\\' ||
			r == '$' || r == '`' || r == '|' || r == '&' || r == ';' ||
			r == '<' || r == '>' || r == '(' || r == ')' || r == '*' ||
			r == '?' || r == '[' || r == ']' || r == '{' || r == '}' {
			return "'" + a + "'"
		}
	}
	return a
}

// stringReader returns an io.Reader for a string, avoiding a bytes.Reader
// import cycle concern.
func stringReader(s string) io.Reader {
	return &stringReaderType{s: s}
}

type stringReaderType struct {
	s   string
	pos int
}

func (r *stringReaderType) Read(p []byte) (int, error) {
	if r.pos >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.pos:])
	r.pos += n
	return n, nil
}
