package executil

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCheckInstalled(t *testing.T) {
	// "true" is a standard utility on POSIX systems; should always be found.
	if !CheckInstalled("true") {
		t.Skip("coreutils 'true' not found on PATH — skipping")
	}
	if CheckInstalled("this-binary-definitely-does-not-exist-1234567") {
		t.Fatal("CheckInstalled returned true for a non-existent binary")
	}
}

func TestRunnerDryRun(t *testing.T) {
	var buf bytes.Buffer
	r := &Runner{
		DryRun: true,
		Log:    func(format string, args ...any) { buf.WriteString(strings.NewReplacer("\n", " ").Replace(format) + "\n") },
		Stdout: &buf,
		Stderr: &buf,
	}
	err := r.RunWithTimeout(5*time.Second, Cmd{Name: "echo", Args: []string{"hello"}})
	if !errors.Is(err, ErrDryRun) {
		t.Fatalf("expected ErrDryRun, got %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("[DRY-RUN]")) {
		t.Fatalf("dry-run log not written: %q", buf.String())
	}
}

func TestRunnerExecutesAndReturns(t *testing.T) {
	if !CheckInstalled("echo") {
		t.Skip("coreutils 'echo' not found on PATH — skipping")
	}
	var out bytes.Buffer
	r := &Runner{
		Log:    func(string, ...any) {},
		Stdout: &out,
		Stderr: &out,
	}
	if err := r.RunWithTimeout(5*time.Second, Cmd{Name: "echo", Args: []string{"metsuke"}}); err != nil {
		t.Fatalf("echo failed: %v", err)
	}
	if !strings.Contains(out.String(), "metsuke") {
		t.Fatalf("expected output 'metsuke', got %q", out.String())
	}
}

func TestRunnerTimeoutCancels(t *testing.T) {
	if !CheckInstalled("sleep") {
		t.Skip("coreutils 'sleep' not found on PATH — skipping")
	}
	r := &Runner{Log: func(string, ...any) {}}
	// 5s sleep, but a 100ms timeout → must error out with ctx deadline.
	err := r.RunWithTimeout(100*time.Millisecond, Cmd{Name: "sleep", Args: []string{"5"}})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// the context cancellation should have killed the child process group
}

func TestRunnerContextCancel(t *testing.T) {
	if !CheckInstalled("sleep") {
		t.Skip("coreutils 'sleep' not found on PATH — skipping")
	}
	r := &Runner{Log: func(string, ...any) {}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := r.Run(ctx, Cmd{Name: "sleep", Args: []string{"10"}})
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

func TestFormatCommand(t *testing.T) {
	got := formatCommand("nuclei", []string{"-l", "live hosts.txt", "-silent"})
	if !strings.Contains(got, "nuclei") || !strings.Contains(got, "live hosts.txt") {
		t.Fatalf("unexpected formatted command: %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in   string
		want bool // expect quotes
	}{
		{"hello", false},
		{"a b", true},
		{"$VAR", true},
		{"", true},
		{"-d", false},
	}
	for _, c := range cases {
		got := shellQuote(c.in)
		if c.want && !strings.ContainsAny(got, "'\"") {
			t.Errorf("shellQuote(%q) = %q, expected quoting", c.in, got)
		}
		if !c.want && strings.ContainsAny(got, "'\"") {
			t.Errorf("shellQuote(%q) = %q, expected no quoting", c.in, got)
		}
	}
}
