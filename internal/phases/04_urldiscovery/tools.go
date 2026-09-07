package urldiscovery

import (
	"os"
	"path/filepath"

	"metsuke/internal/executil"
	"metsuke/internal/pipeline"
)

// runGau runs gau (passive URL source) and appends to sourcesRaw.
func (p *Phase) runGau(s *pipeline.State, sourcesRaw string) error {
	if !executil.CheckInstalled("gau") {
		s.Log.Warn("gau is not installed, skipping this passive source.")
		return nil
	}
	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] printf '%%s\\n' %s | gau --threads %d --subs", s.Cfg.Domain, s.Cfg.Threads)
		return nil
	}
	s.Log.Info("Collecting historical URLs from gau (passive source)...")
	f, err := os.OpenFile(sourcesRaw, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	oldStdout := p.runner.Stdout
	p.runner.Stdout = f
	err = p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "gau",
		Args: []string{"--threads", itoa(s.Cfg.Threads), "--subs"},
		Stdin: s.Cfg.Domain + "\n",
	})
	p.runner.Stdout = oldStdout
	return err
}

// runURLFinder runs urlfinder (--web-archives) and appends to sourcesRaw.
func (p *Phase) runURLFinder(s *pipeline.State, sourcesRaw string) error {
	if !executil.CheckInstalled("urlfinder") {
		s.Log.Warn("--web-archives requested but urlfinder is missing, skipping.")
		return nil
	}
	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] urlfinder -d %s -silent", s.Cfg.Domain)
		return nil
	}
	s.Log.Info("Collecting historical URLs via urlfinder (--web-archives)...")
	f, err := os.OpenFile(sourcesRaw, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	oldStdout := p.runner.Stdout
	p.runner.Stdout = f
	err = p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "urlfinder",
		Args: []string{"-d", s.Cfg.Domain, "-silent"},
	})
	p.runner.Stdout = oldStdout
	return err
}

// runKatana runs katana (active JS-aware crawl) and appends to sourcesRaw.
func (p *Phase) runKatana(s *pipeline.State, sourcesRaw string) error {
	if s.Cfg.PassiveOnly {
		s.Log.Info("passive-only mode: --katana skipped (it is an active crawl)")
		return nil
	}
	if !executil.CheckInstalled("katana") {
		s.Log.Warn("--katana requested but katana is missing, skipping.")
		return nil
	}
	liveHosts := filepath.Join(s.OutDir, "httpx", "live_hosts.txt")
	if !pipeline.IsNonEmpty(liveHosts) {
		s.Log.Warn("No live hosts for katana crawl, skipping.")
		return nil
	}
	if s.Cfg.DryRun {
		s.Log.Info("[DRY-RUN] katana -list live_hosts.txt -js-crawl -silent")
		return nil
	}
	s.Log.Info("Running katana (active JS-aware crawling)...")
	f, err := os.OpenFile(sourcesRaw, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	oldStdout := p.runner.Stdout
	p.runner.Stdout = f
	args := []string{"-list", liveHosts, "-js-crawl", "-silent"}
	for _, h := range s.Headers {
		args = append(args, "-H", h)
	}
	err = p.runner.RunWithTimeout(0, executil.Cmd{
		Name: "katana",
		Args: args,
	})
	p.runner.Stdout = oldStdout
	return err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	if n < 0 {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
