// Package config holds the parsed, validated configuration for a metsuke
// run. It is the Go equivalent of the bash version's global variables plus
// its `validate_inputs()` function.
//
// Configuration precedence (highest first):
//  1. CLI flags (cobra)
//  2. Environment variables (BURP_API_KEY, RECON_WEBHOOK_URL)
//  3. YAML config file (--config)
//  4. Built-in defaults
//
// The bash version's `source $CONFIG_FILE` was an arbitrary shell-code
// execution vector; YAML parsing closes that gap while keeping
// human-readable config files.
package config

import (
	"time"
)

// Defaults mirrors the bash version's built-in defaults.
const (
	DefaultThreads          = 50
	DefaultTimeout          = 10
	DefaultRateLimit        = 0 // 0 = unlimited
	DefaultNucleiSeverity   = "low,medium,high,critical"
	DefaultMaxJSFiles       = 500
	DefaultJSConcurrency   = 10
	DefaultBurpProxyHost   = "127.0.0.1"
	DefaultBurpProxyPort   = "8080"
	DefaultBurpAPIURL      = "http://127.0.0.1:1337"
)

// Config is the fully-resolved, validated configuration for a single run.
type Config struct {
	// Target
	Domain   string
	OutDir   string
	Version  bool
	JsonLog  bool

	// Concurrency / performance
	Threads    int
	Timeout    int
	RateLimit  int
	Parallel   bool

	// Scan modes
	FullScan   bool
	Resume     bool
	SkipCDN    bool
	DryRun     bool
	PassiveOnly bool

	// URL discovery
	Katana            bool
	WebArchives       bool
	ExtendedWorkflows bool
	SessionHeaders    []string
	SessionHeaderFile string

	// Scope filtering
	ExcludeSubs []string

	// Nuclei
	NucleiSeverity    string
	NucleiTags        string
	UpdateTemplates   bool
	NoInteractsh      bool

	// Notification
	WebhookURL string
	NoNotify   bool

	// Burp Suite
	BurpPassive    bool
	BurpActiveScan bool
	BurpProxy      string // host:port
	BurpAPIURL     string
	BurpAPIKey     string

	// JS secret scan tuning
	MaxJSFiles     int
	JSConcurrency  int

	// Internal / derived (not set by user)
	StartedAt   time.Time
	ConfigFile  string
}
