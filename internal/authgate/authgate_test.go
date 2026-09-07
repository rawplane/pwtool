package authgate

import (
	"bytes"
	"strings"
	"testing"

	"metsuke/internal/audit"
)

func TestConfirmDryRunSkipsPrompt(t *testing.T) {
	var out bytes.Buffer
	auditLog, _ := audit.New("")
	err := Confirm(Options{Domain: "example.com", DryRun: true}, &bytes.Buffer{}, &out, auditLog)
	if err != nil {
		t.Fatalf("dry-run Confirm returned error: %v", err)
	}
	if !strings.Contains(out.String(), "DRY-RUN") {
		t.Fatalf("expected dry-run banner, got %q", out.String())
	}
}

func TestConfirmExactMatch(t *testing.T) {
	var out bytes.Buffer
	stdin := strings.NewReader(ConfirmationPhrase + "\n")
	auditLog, _ := audit.New("")
	err := Confirm(Options{Domain: "example.com"}, stdin, &out, auditLog)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !strings.Contains(out.String(), "Authorization confirmed") {
		t.Fatalf("expected success banner, got %q", out.String())
	}
}

func TestConfirmMismatchRefuses(t *testing.T) {
	var out bytes.Buffer
	stdin := strings.NewReader("i have authorization\n") // wrong case
	auditLog, _ := audit.New("")
	err := Confirm(Options{Domain: "example.com"}, stdin, &out, auditLog)
	if err == nil {
		t.Fatal("expected refusal error, got nil")
	}
	if !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("expected refusal error, got %v", err)
	}
}

func TestConfirmEmptyInputRefuses(t *testing.T) {
	var out bytes.Buffer
	stdin := strings.NewReader("")
	auditLog, _ := audit.New("")
	err := Confirm(Options{Domain: "example.com"}, stdin, &out, auditLog)
	if err == nil {
		t.Fatal("expected refusal for empty input, got nil")
	}
}

func TestConfirmWarningsDisplayed(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"passive-only", Options{Domain: "ex.com", PassiveOnly: true}, "passive-only"},
		{"extended", Options{Domain: "ex.com", ExtendedWorkflows: true}, "extended-workflows"},
		{"burp-active", Options{Domain: "ex.com", BurpActiveScan: true}, "ACTIVE SCAN"},
	}
	auditLog, _ := audit.New("")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			stdin := strings.NewReader(ConfirmationPhrase + "\n")
			if err := Confirm(c.opts, stdin, &out, auditLog); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(out.String(), c.want) {
				t.Errorf("expected output to contain %q, got %q", c.want, out.String())
			}
		})
	}
}
