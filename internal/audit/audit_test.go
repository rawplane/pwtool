package audit

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRedactArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no secrets",
			in:   []string{"-d", "example.com", "--threads", "50"},
			want: []string{"-d", "example.com", "--threads", "50"},
		},
		{
			name: "session header redacted",
			in:   []string{"-d", "example.com", "--session-header", "Cookie: secret=abc"},
			want: []string{"-d", "example.com", "--session-header", "REDACTED"},
		},
		{
			name: "burp api key redacted",
			in:   []string{"--burp-api-key", "supersecret123"},
			want: []string{"--burp-api-key", "REDACTED"},
		},
		{
			name: "multiple secrets",
			in:   []string{"--session-header", "h1", "--burp-api-key", "k1"},
			want: []string{"--session-header", "REDACTED", "--burp-api-key", "REDACTED"},
		},
		{
			name: "empty args",
			in:   []string{},
			want: []string{},
		},
		{
			name: "trailing secret flag with no value",
			in:   []string{"-d", "example.com", "--session-header"},
			want: []string{"-d", "example.com", "--session-header"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactArgs(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len mismatch: got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("arg %d: got %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestLoggerWritesToStderr(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{err: &buf}
	l.Log("event=test target=example.com")
	out := buf.String()
	if !strings.Contains(out, "[AUDIT]") {
		t.Fatalf("stderr mirror missing [AUDIT] prefix: %q", out)
	}
	if !strings.Contains(out, "event=test") {
		t.Fatalf("stderr mirror missing message: %q", out)
	}
}

func TestLoggerWritesToFile(t *testing.T) {
	tmp := t.TempDir()
	l, err := New(tmp + "/audit.log")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer l.Close()
	l.Log("event=workspace-created")
	data, err := readFileSafe(tmp + "/audit.log")
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !strings.Contains(string(data), "event=workspace-created") {
		t.Fatalf("audit file missing event: %q", string(data))
	}
}

// readFileSafe is a tiny helper to avoid importing os in the test directly.
func readFileSafe(path string) ([]byte, error) {
	return os.ReadFile(path)
}
