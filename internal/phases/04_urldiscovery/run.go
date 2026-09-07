package urldiscovery

import (
	"context"
	"os"
	"path/filepath"

	"metsuke/internal/pipeline"
)

// Run executes the URL discovery phase.
func (p *Phase) Run(ctx context.Context, s *pipeline.State) error {
	out := filepath.Join(s.OutDir, "urls")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	sourcesRaw := filepath.Join(out, ".sources_raw.txt")
	_ = os.Remove(sourcesRaw)

	if err := p.runGau(s, sourcesRaw); err != nil {
		s.Log.Warn("gau failed: %v", err)
	}
	if s.Cfg.WebArchives {
		if err := p.runURLFinder(s, sourcesRaw); err != nil {
			s.Log.Warn("urlfinder failed: %v", err)
		}
	}
	if s.Cfg.Katana {
		if err := p.runKatana(s, sourcesRaw); err != nil {
			s.Log.Warn("katana failed: %v", err)
		}
	}

	if !pipeline.IsNonEmpty(sourcesRaw) {
		s.Log.Warn("No URL sources were successfully collected, skipping the rest of this phase.")
		_ = os.Remove(sourcesRaw)
		return nil
	}

	// Sort unique raw URLs.
	rawData, _ := os.ReadFile(sourcesRaw)
	rawURLs := splitAndDedupe(string(rawData))
	allRawPath := filepath.Join(out, "all_urls_raw.txt")
	writeLines(allRawPath, rawURLs)

	// Normalize & dedupe.
	s.Log.Info("Normalizing & deduplicating URLs (path templating + parameter signature)...")
	allPath := filepath.Join(out, "all_urls.txt")
	if err := normalizeDedupeFile(allRawPath, allPath); err != nil {
		return err
	}
	_ = os.Remove(sourcesRaw)

	// Derivative filters.
	writeLines(filepath.Join(out, "js_files.txt"),
		filterLines(rawURLs, `\.js(\?|$)`))
	writeLines(filepath.Join(out, "urls_with_params.txt"),
		filterLines(rawURLs, `\?.=`))
	writeLines(filepath.Join(out, "interesting_urls.txt"),
		filterLines(rawURLs, `(?i)(admin|api|backup|config|\.env|swagger|graphql|internal|debug)`))

	return nil
}
