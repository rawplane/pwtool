// Package notify implements a best-effort webhook notifier.
//
// Notifications are fire-and-forget: a failure to deliver must never abort
// the pipeline. This mirrors the bash version's `notify()` which silently
// swallows curl errors.
package notify

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"
)

// Notifier posts a short text message to a webhook endpoint.
type Notifier struct {
	URL     string
	Enabled bool
	Client  *http.Client
}

// New returns a Notifier that posts to url. If url is empty or enabled is
// false, Send becomes a no-op (and returns nil).
func New(url string, enabled bool) *Notifier {
	return &Notifier{
		URL:     url,
		Enabled: enabled && url != "",
		Client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Send posts a message to the webhook as a Slack/Discord-compatible JSON
// payload: {"text": "[metsuke] <message>"}. Any HTTP error is silently
// ignored so that notification failures never break the pipeline.
func (n *Notifier) Send(ctx context.Context, message string) {
	if n == nil || !n.Enabled {
		return
	}
	payload := fmt.Sprintf(`{"text":"[metsuke] %s"}`, jsonEscape(message))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewBufferString(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// Best-effort: swallow any error from the POST.
	_, _ = n.Client.Do(req)
}

// jsonEscape returns a minimal JSON-escaped representation of s, suitable
// for embedding inside a JSON string literal. It handles the characters
// that are most likely to appear in notification messages.
func jsonEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
