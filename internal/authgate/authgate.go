// Package authgate implements the interactive authorization confirmation
// that must precede every non-dry-run metsuke execution.
//
// This is a core safety mechanism: the pipeline refuses to start unless the
// operator types the exact phrase "I HAVE AUTHORIZATION", confirming that
// the target is in scope. The gate is skipped only in --dry-run mode.
package authgate

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"metsuke/internal/audit"
)

// ConfirmationPhrase is the exact string the operator must type to pass the
// authorization gate. It is deliberately uppercase and space-separated so
// that accidental whitespace or case variations cause a refusal.
const ConfirmationPhrase = "I HAVE AUTHORIZATION"

// Options carries the run-level flags that affect the wording of the gate.
type Options struct {
	Domain            string
	DryRun            bool
	PassiveOnly       bool
	ExtendedWorkflows bool
	BurpActiveScan    bool
}

// Confirm prompts the operator for the authorization phrase and returns nil
// if the typed input matches ConfirmationPhrase exactly. On dry-run it logs
// a dry-run audit event and returns nil without prompting.
//
// stdin and stdout are parameters so that tests can inject a fake TTY; in
// production both default to os.Stdin / os.Stdout.
func Confirm(opts Options, stdin io.Reader, stdout io.Writer, auditLog *audit.Logger) error {
	if opts.DryRun {
		if auditLog != nil {
			auditLog.Logf("event=authorization mode=dry-run target=%s", opts.Domain)
		}
		fmt.Fprintln(stdout, "DRY-RUN mode: no requests will be sent; skipping interactive prompt.")
		return nil
	}

	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "════════════════════════════════════════════════════════════")
	fmt.Fprintln(stdout, " AUTHORIZATION CONFIRMATION")
	fmt.Fprintln(stdout, "════════════════════════════════════════════════════════════")
	fmt.Fprintf(stdout, "Target : %s\n", opts.Domain)
	fmt.Fprintln(stdout, "Make sure you have explicit permission to perform security")
	fmt.Fprintln(stdout, "testing against this target (bug bounty scope / pentest contract /")
	fmt.Fprintln(stdout, "your own asset).")

	if opts.PassiveOnly {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "NOTE: --passive-only is enabled: no direct requests will")
		fmt.Fprintln(stdout, "be sent to the target — only third-party OSINT sources are queried.")
	}

	if opts.ExtendedWorkflows {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "NOTE: --extended-workflows is enabled.")
		fmt.Fprintln(stdout, "This phase specifically searches for endpoints that could")
		fmt.Fprintln(stdout, "potentially leak credentials/configuration (.env, .git, admin panel,")
		fmt.Fprintln(stdout, "cloud config, token/session endpoints), and fetches JS files to look")
		fmt.Fprintln(stdout, "for hardcoded secrets. These remain passive GET requests, but make")
		fmt.Fprintln(stdout, "sure your scope allows searching for this kind of sensitive information.")
	}

	if opts.BurpActiveScan {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "ADDITIONAL WARNING: --burp-active-scan is enabled.")
		fmt.Fprintln(stdout, "This will trigger an ACTIVE SCAN (intrusive/actively attacking endpoints)")
		fmt.Fprintln(stdout, "via the Burp Suite REST API. Make sure your authorization scope")
		fmt.Fprintln(stdout, "explicitly allows active scanning, not just passive recon.")
	}

	fmt.Fprintln(stdout, "")
	fmt.Fprintf(stdout, "Type '%s' to continue: ", ConfirmationPhrase)

	reader := bufio.NewReader(stdin)
	input, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read authorization input: %w", err)
	}
	input = strings.TrimRight(input, "\r\n")

	if input != ConfirmationPhrase {
		if auditLog != nil {
			auditLog.Logf("event=authorization result=REFUSED target=%s", opts.Domain)
		}
		return fmt.Errorf("authorization not confirmed (input did not match)")
	}

	if auditLog != nil {
		auditLog.Logf("event=authorization result=confirmed target=%s", opts.Domain)
	}
	fmt.Fprintln(stdout, "[OK] Authorization confirmed. Continuing pipeline...")
	return nil
}
