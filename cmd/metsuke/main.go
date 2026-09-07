// Command metsuke is a modular recon pipeline with authorization discipline
// and auditing. It is a Go rewrite of the bash version metsuke.sh v4.0.0.
package main

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"metsuke/internal/config"
	"metsuke/internal/version"
)

func main() {
	cfg := &config.Config{}

	rootCmd := &cobra.Command{
		Use:   "metsuke",
		Short: "Modular recon pipeline with authorization discipline & auditing",
		Long: "Modular recon pipeline with authorization discipline & auditing.\n\n" +
			"IMPORTANT: Only use this against targets for which you already have explicit permission.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printBanner()
			return runPipeline(cfg, os.Args[1:])
		},
		SilenceUsage: true,
	}

	flags := rootCmd.Flags()

	// Basic options
	flags.StringVarP(&cfg.Domain, "domain", "d", "", "Target domain (required)")
	flags.StringVarP(&cfg.OutDir, "out", "o", "", "Output directory (default: ./recon_<domain>_<timestamp>)")
	flags.IntVarP(&cfg.Threads, "threads", "t", config.DefaultThreads, "Concurrent threads (1-500)")
	flags.BoolVar(&cfg.FullScan, "full", false, "Aggressive mode: full port scan + all nuclei severities")
	flags.StringVar(&cfg.ConfigFile, "config", "", "YAML config file for defaults")
	flags.IntVar(&cfg.Timeout, "timeout", config.DefaultTimeout, "Per-request HTTP timeout (3-300 seconds)")
	flags.IntVar(&cfg.RateLimit, "rate-limit", 0, "Requests/second cap (0 = unlimited)")
	flags.BoolVarP(&cfg.Version, "version", "v", false, "Print version and exit")
	flags.BoolVar(&cfg.JsonLog, "json-log", false, "Emit structured JSON log output")

	// Scope & safety options
	flags.StringArrayVar(&cfg.ExcludeSubs, "exclude-sub", nil, "ERE to prune subdomains (repeatable)")
	flags.BoolVar(&cfg.PassiveOnly, "passive-only", false, "Zero-contact OSINT mode")
	flags.BoolVar(&cfg.NoInteractsh, "no-interactsh", false, "Disable nuclei OOB callbacks")
	flags.BoolVar(&cfg.NoNotify, "no-notify", false, "Disable webhook notifications")
	flags.BoolVar(&cfg.Resume, "resume", false, "Skip phases whose output already exists")
	flags.BoolVar(&cfg.DryRun, "dry-run", false, "Show commands without executing")
	flags.BoolVar(&cfg.SkipCDN, "skip-cdn", false, "Skip port scanning for CDN-fronted hosts")

	// Performance options
	flags.BoolVar(&cfg.Parallel, "parallel", false, "Run port scan & URL discovery concurrently")

	// URL discovery
	flags.BoolVar(&cfg.Katana, "katana", false, "Active JS-aware crawling with katana")
	flags.BoolVar(&cfg.WebArchives, "web-archives", false, "Use urlfinder (Wayback/CT)")
	flags.BoolVar(&cfg.ExtendedWorkflows, "extended-workflows", false, "Sensitive endpoint + JS secret scanning")
	flags.StringArrayVar(&cfg.SessionHeaders, "session-header", nil, "Extra header for crawling (repeatable)")
	flags.StringVar(&cfg.SessionHeaderFile, "session-header-file", "", "File with headers (chmod 600)")

	// Nuclei
	flags.StringVar(&cfg.NucleiSeverity, "nuclei-severity", config.DefaultNucleiSeverity, "Comma list of severities")
	flags.StringVar(&cfg.NucleiTags, "nuclei-tags", "", "Restrict nuclei to specific tags")
	flags.BoolVar(&cfg.UpdateTemplates, "update-templates", false, "Run nuclei -update-templates first")

	// Burp Suite
	flags.BoolVar(&cfg.BurpPassive, "burp", false, "Mirror httpx traffic to Burp proxy")
	flags.StringVar(&cfg.BurpProxy, "burp-proxy", "127.0.0.1:8080", "Burp proxy address")
	flags.BoolVar(&cfg.BurpActiveScan, "burp-active-scan", false, "Trigger active scan via REST API (INTRUSIVE)")
	flags.StringVar(&cfg.BurpAPIURL, "burp-api-url", "http://127.0.0.1:1337", "Burp REST API URL")
	flags.StringVar(&cfg.BurpAPIKey, "burp-api-key", "", "Burp REST API key")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	if cfg.Version {
		// Handled inside rootCmd if flag is set, but fallback here.
		_ = version.String()
	}
}

// runPipeline is the actual entry point, separated from cobra setup.
// It is called by rootCmd.RunE.
func runPipeline(cfg *config.Config, rawArgs []string) error {
	// --version short-circuits everything.
	if cfg.Version {
		println(version.String())
		return nil
	}

	// Load config file if specified (before ApplyDefaults so config file
	// provides base values that CLI flags override).
	if cfg.ConfigFile != "" {
		if err := config.LoadYAMLFile(cfg, cfg.ConfigFile); err != nil {
			return err
		}
	}

	cfg.ApplyDefaults()
	cfg.StartedAt = time.Now()

	if err := cfg.Validate(); err != nil {
		return err
	}

	return execute(cfg, rawArgs)
}
