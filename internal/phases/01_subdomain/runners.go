package subdomain

import (
	"os"
	"path/filepath"

	"metsuke/internal/executil"
	"metsuke/internal/pipeline"
)

// dryRun prints the commands that would run for Phase 1.
func (p *Phase) dryRun(s *pipeline.State, out string) {
	s.Log.Info("[DRY-RUN] subfinder -d %s -all -silent -o %s/subfinder.txt", s.Cfg.Domain, out)
	s.Log.Info("[DRY-RUN] assetfinder --subs-only %s", s.Cfg.Domain)
	s.Log.Info("[DRY-RUN] curl 'https://crt.sh/?q=%%25.%s&output=json'", s.Cfg.Domain)
	s.Log.Info("[DRY-RUN] filter: lowercase + anchored scope match (^|\\.)%s$ + --exclude-sub", s.Cfg.Domain)
}

// runAssetfinder runs assetfinder if installed, redirecting stdout to a file.
func (p *Phase) runAssetfinder(s *pipeline.State, out string) {
	if !executil.CheckInstalled("assetfinder") {
		return
	}
	assetfinderOut := filepath.Join(out, "assetfinder.txt")
	f, err := os.Create(assetfinderOut)
	if err != nil {
		s.Log.Warn("create assetfinder out: %v", err)
		return
	}
	oldStdout := p.runner.Stdout
	p.runner.Stdout = f
	err = p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "assetfinder",
		Args: []string{"--subs-only", s.Cfg.Domain},
	})
	p.runner.Stdout = oldStdout
	f.Close()
	if err != nil && err != executil.ErrDryRun {
		s.Log.Warn("assetfinder failed: %v", err)
	}
}

// countLines wraps pipeline.CountLines for local use.
func countLines(path string) int {
	return pipeline.CountLines(path)
}
