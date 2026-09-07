package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// crtshEntry is a single row from crt.sh's JSON output.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// fetchCrtsh queries crt.sh for the domain, extracts name_value fields,
// normalizes them, and writes one host per line to outFile. Mirrors the
// bash version's `curl ... | jq -r '.[].name_value' | ... | sort -u`.
func fetchCrtsh(ctx context.Context, domain, outFile string) error {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	// Retry up to 3 times with 5s delay, like the bash retry() helper.
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := doCrtshRequest(ctx, url, outFile)
		if err == nil {
			return nil
		}
		lastErr = err
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("crt.sh failed after retries: %w", lastErr)
}

func doCrtshRequest(ctx context.Context, url, outFile string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var entries []crtshEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parse crt.sh JSON: %w", err)
	}
	// Write normalized hosts, deduplicated.
	seen := make(map[string]struct{})
	out := []byte{}
	for _, e := range entries {
		for _, line := range splitLines(e.NameValue) {
			h := normalizeHost(line)
			if h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, []byte(h)...)
			out = append(out, '\n')
		}
	}
	return writeFile(outFile, out)
}
