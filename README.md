# metsuke

**Modular recon pipeline with authorization discipline & auditing**

The name comes from an Edo-era inspector title (*metsuke*, 目付) — an
officially mandated role, with a clear mandate, to observe and report
before acting. This tool follows the same philosophy: **authorize first,
then act.**

> **Version:** 4.1.0 (Go rewrite of `metsuke.sh` v4.0.0)

---

## Legal Warning

This tool may **ONLY** be run against targets for which you already have
**explicit permission** — a bug bounty scope, a signed pentest contract, or
your own assets. Scanning without authorization is illegal in most
jurisdictions.

- `--burp-active-scan` is **INTRUSIVE** (it attacks endpoints). Make sure
  your authorization scope explicitly allows active scanning, not just
  passive recon.
- `--extended-workflows` searches for endpoints that could potentially
  leak credentials or configuration (`.env`, `.git`, admin panels, cloud
  config, token/session endpoints), and fetches JS files to look for
  hardcoded secrets. These remain passive `GET` requests (not exploits),
  but make sure your scope allows this kind of sensitive information search.

Every non-dry-run execution requires you to type an explicit confirmation
phrase before any request is sent to the target.

---

## Features

- **Modular pipeline** — subdomain enumeration, live host probing, port
  scanning, URL/endpoint discovery, JS secret scanning, takeover checks,
  screenshots, vulnerability scanning, and optional Burp active scan.
- **Authorization gate** — an interactive confirmation prompt before any
  network activity (skipped only in `--dry-run`).
- **Full audit trail** — every run writes a timestamped `audit.log` (with
  secrets redacted from the recorded arguments) alongside the full
  pipeline log.
- **Scope enforcement** — subdomains are matched with an anchored regex
  against the target domain (not a naive substring match), with optional
  `--exclude-sub` regex filters applied before any request is sent.
- **Passive-only mode** — a zero-contact OSINT mode that only queries
  third-party sources (subfinder, crt.sh, gau) and never touches the
  target directly.
- **Resumable** — `--resume` skips phases whose output already exists.
- **Config file support** — load defaults from a YAML file (CLI flags
  always win).
- **Rate limiting & timeouts** — tunable per-request timeout and
  requests/second cap.
- **Secure secret handling** — session headers and API keys can be
  supplied via files (chmod 600) instead of the command line, where
  they'd be visible in `ps`.
- **Optional Burp Suite integration** — passive traffic mirroring to
  populate the Site Map, and optional active scan triggering via the
  Burp REST API.
- **Single-instance locking** — prevents two runs from clobbering the
  same output directory (OS-level `flock` + PID file).
- **Graceful interrupt handling** — `Ctrl-C` stops child processes via
  process-group signaling, logs the interruption, and exits with code
  130.
- **Structured JSON logging** — optional `--json-log` for log
  aggregators (ELK, Loki, etc.).
- **Structured output & summary** — per-phase artifacts plus a final
  `summary.txt` / `summary.json` report.

---

## Requirements

### Required dependencies (external binaries)

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [naabu](https://github.com/projectdiscovery/naabu)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- `curl`
- `jq`

> In `--passive-only` mode, `httpx`, `naabu`, and `nuclei` are not
> required.

### Optional dependencies

- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [gau](https://github.com/lc/gau)
- [gowitness](https://github.com/sensepost/gowitness)
- [katana](https://github.com/projectdiscovery/katana)
- [urlfinder](https://github.com/projectdiscovery/urlfinder)

### Build requirements

- **Go 1.21+** (uses `cobra`/`pflag` for CLI parsing; everything else
  is stdlib)

> **Design decision:** ProjectDiscovery tools are invoked via shell-out
> rather than imported as Go libraries. This avoids the heavy transitive
> dependency tree, CGO/libpcap requirements, and frequent breaking API
> changes of the PD library ecosystem. metsuke remains a stable,
> lightweight orchestrator.

---

## Installation

### Build from source

```bash
git clone <repo-url> metsuke
cd metsuke

VERSION=4.1.0
COMMIT=$(git rev-parse --short HEAD)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

go build -ldflags "\
  -X metsuke/internal/version.Version=$VERSION \
  -X metsuke/internal/version.GitCommit=$COMMIT \
  -X metsuke/internal/version.BuildDate=$BUILD_DATE" \
  -o metsuke ./cmd/metsuke/

chmod +x metsuke
./metsuke --version
```

### Install external tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/assetfinder@latest
sudo apt install jq curl -y
```

Make sure `$GOPATH/bin` is in your `$PATH`. metsuke will **not**
automatically install tools or modify your shell profile — install
everything manually first.

### Run tests

```bash
go test ./... -count=1 -v
```

---

## Usage

```bash
./metsuke -d <domain> [options]
```

### Basic options

| Flag | Description |
|---|---|
| `-d, --domain <domain>` | Target domain (required), e.g. `example.com` |
| `-o, --out <dir>` | Output directory (default: `./recon_<domain>_<timestamp>`) |
| `-t, --threads <int>` | Concurrent threads (default: 50, range: 1-500) |
| `--full` | Aggressive mode: full port scan (1-65535) + all nuclei severities |
| `--config <file>` | Load defaults from a YAML config file (CLI flags always win) |
| `--timeout <sec>` | Per-request HTTP timeout (default: 10, range: 3-300) |
| `--rate-limit <rps>` | Requests/second cap for httpx/naabu/nuclei (default: off) |
| `--json-log` | Emit structured JSON log output (optional, does not replace default log) |
| `-v, --version` | Print version, git commit, and build date, then exit |
| `-h, --help` | Show help |

### Scope & safety options

| Flag | Description |
|---|---|
| `--exclude-sub <regex>` | ERE matched per line; matching subdomains are pruned **before** any request is sent (repeatable) |
| `--passive-only` | Zero-contact mode: only third-party OSINT sources (subfinder / crt.sh / gau); no direct requests to the target |
| `--no-interactsh` | Disable nuclei out-of-band (interact.sh) callbacks |
| `--no-notify` | Disable webhook notifications for this run |
| `--resume` | Skip phases whose output already exists from a previous run |
| `--dry-run` | Show the commands that would run, without executing them |
| `--skip-cdn` | Skip port scanning for hosts detected behind a CDN/WAF |

### Performance options

| Flag | Description |
|---|---|
| `--parallel` | Run port scan & URL discovery concurrently (higher combined request rate) |

> Sequential mode is the default (safest). Use `--parallel` only when your
> scope allows a higher combined request rate.

### Advanced URL discovery options

| Flag | Description |
|---|---|
| `--katana` | Active, JS-aware crawling with katana, in addition to gau |
| `--web-archives` | Use urlfinder (Wayback/CT/etc.) in addition to gau |
| `--extended-workflows` | Sensitive endpoint detection (admin/auth/cloud/.env/.git) + JS hardcoded-secret scanning (passive GETs only) |
| `--session-header "H: V"` | Extra header for crawling (e.g. `Cookie`), repeatable. **Visible in `ps`** — prefer `--session-header-file` |
| `--session-header-file <f>` | File with one `Header: value` per line (chmod 600) |

### Nuclei options

| Flag | Description |
|---|---|
| `--nuclei-severity <list>` | Comma list (default: `low,medium,high,critical`) |
| `--nuclei-tags <tags>` | Restrict nuclei to specific tags (default: all) |
| `--update-templates` | Run `nuclei -update-templates` before scanning |

### Burp Suite integration (optional, default OFF)

| Flag | Description |
|---|---|
| `--burp` | Mirror httpx traffic to the Burp proxy (populates Site Map) |
| `--burp-proxy <host:port>` | Burp proxy address (default: `127.0.0.1:8080`) |
| `--burp-active-scan` | Trigger an **active scan** via the Burp REST API (**INTRUSIVE**) |
| `--burp-api-url <url>` | Burp REST API address (default: `http://127.0.0.1:1337`) |
| `--burp-api-key <key>` | Burp REST API key. **Visible in `ps`** — prefer the `BURP_API_KEY` env var or a chmod-600 config file |

### Environment variables

| Variable | Description |
|---|---|
| `RECON_WEBHOOK_URL` | Webhook URL for phase-completion notifications |
| `BURP_API_KEY` | Burp REST API key (preferred over `--burp-api-key`) |

---

## Config file

metsuke supports YAML config files for defaults. CLI flags always
override config file values.

```yaml
# metsuke.yaml
threads: 100
timeout: 30
nuclei_severity: high,critical
webhook_url: https://hooks.example.com/test
exclude_subs:
  - "^dev\\."
  - "^test\\."
session_headers:
  - "Cookie: session=abc"
  - "X-Custom: value"
```

```bash
./metsuke -d example.com --config metsuke.yaml
```

> **Security note:** The bash version used `source $CONFIG_FILE` (arbitrary
> shell-code execution). The Go version uses safe YAML parsing, eliminating
> this attack vector.

---

## Examples

```bash
# Basic run (interactive authorization required)
./metsuke -d example.com

# Custom output dir, more threads, full aggressive scan, resumable
./metsuke -d example.com -o ./results -t 100 --full --resume

# Zero-contact OSINT only
./metsuke -d example.com --passive-only

# Exclude known out-of-scope subdomains, active JS-aware crawl
./metsuke -d example.com --exclude-sub '^(dev|internal|vpn)\.' --katana

# Authenticated crawling with headers kept out of the command line
./metsuke -d example.com --session-header-file ./cookies.txt --katana

# Sensitive endpoint / secret hunting, no OOB callbacks
./metsuke -d example.com --extended-workflows --no-interactsh

# Mirror traffic into Burp's Site Map
./metsuke -d example.com --burp --burp-proxy 127.0.0.1:8080

# Trigger a Burp active scan (intrusive — scope must explicitly allow this)
./metsuke -d example.com --burp-active-scan --burp-api-key abcd1234

# Dry-run (show commands without executing)
./metsuke -d example.com --dry-run

# Parallel mode (port scan + URL discovery concurrently)
./metsuke -d example.com --parallel

# Structured JSON logging for log aggregators
./metsuke -d example.com --json-log
```

---

## Pipeline phases

1. **Subdomain Enumeration** — subfinder, assetfinder, and crt.sh,
   merged, lowercased, and filtered to an anchored in-scope regex;
   `--exclude-sub` patterns are applied last.
2. **Live Host Probing (httpx)** — status codes, titles, tech stack,
   CDN detection; optionally mirrored to a Burp proxy.
3. **Port Scanning (naabu)** — top-1000 ports by default, or full
   1-65535 with `--full`; can skip CDN-fronted hosts with `--skip-cdn`.
4. **URL & Endpoint Discovery** — gau / urlfinder (passive) and
   optional katana (active, JS-aware) crawling, followed by path
   templating and parameter-signature deduplication. With
   `--extended-workflows`, sensitive endpoint candidates are
   additionally verified live via passive `GET` requests.
5. **JS Hardcoded-Secret Detection** (`--extended-workflows` only) —
   downloads discovered JS files and scans for common credential/token
   patterns (AWS keys, GitHub tokens, Slack webhooks, JWTs, private key
   headers, etc.). Findings are **candidates only** and must be
   verified manually.
6. **Subdomain Takeover Check** — nuclei's takeover templates against
   all in-scope subdomains.
7. **Screenshots** (optional) — via `gowitness`, if installed.
8. **Vulnerability Scanning (nuclei)** — configurable severity and
   tags.
9. **Burp Suite Active Scan** (optional, `--burp-active-scan`) —
   submits live hosts to the Burp REST API to trigger an active scan.

A final **Summary** phase writes `report/summary.txt` and
`report/summary.json` with counts for every phase.

> When `--parallel` is set, phases 3 and 4 run concurrently using
> goroutines with an errgroup-style barrier. Errors in either phase are
> logged but do not abort the other (matching the bash version's
> tolerant `wait`).

---

## Output layout

```
recon_<domain>_<timestamp>/
├── scope.txt                  # target domain
├── pipeline.log              # full run log
├── audit.log                  # timestamped, redacted audit trail
├── subdomains/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── crtsh.txt
│   └── all_subdomains.txt
├── httpx/
│   ├── httpx_full.json
│   ├── live_hosts.txt
│   └── cdn_hosts.txt
├── ports/
│   └── open_ports.txt
├── urls/
│   ├── all_urls_raw.txt
│   ├── all_urls.txt
│   ├── js_files.txt
│   ├── urls_with_params.txt
│   ├── interesting_urls.txt
│   └── extended_sensitive_endpoints.txt   # (--extended-workflows)
├── vulns/
│   ├── js_secrets.txt                     # (--extended-workflows)
│   ├── takeover_results.jsonl
│   └── nuclei_results.jsonl
├── screenshots/
│   └── .done
└── report/
    ├── summary.txt
    ├── summary.json
    └── burp_scan_response.json            # (--burp-active-scan)
```

The output directory is created with mode 0700, so results — including
any session headers or findings — stay private to the invoking user.

---

## Safety mechanisms

- **Interactive authorization gate** — requires typing
  `I HAVE AUTHORIZATION` before any request is sent (skipped only in
  `--dry-run`).
- **Redacted audit log** — `--session-header` and `--burp-api-key`
  values are stripped from the recorded command line.
- **Anchored scope matching** — subdomains are matched with
  `(^|\.)domain$`, not a substring, to avoid accidentally including
  out-of-scope look-alike hosts.
- **Config/secret file permission checks** — warns if a session header
  file isn't `chmod 600`/`400`.
- **Single-instance lock** — a stale or active lock in the output
  directory prevents concurrent runs from colliding (OS-level `flock` +
  PID file for stale-lock detection).
- **Graceful interrupt handling** — `Ctrl-C` stops child processes
  via process-group signaling, logs the interruption, and exits with
  code 130.

---

## Project structure

```
metsuke/
├── cmd/metsuke/
│   ├── main.go              # CLI entrypoint (cobra), banner, flags
│   ├── execute.go           # Pipeline orchestration, signal handling
│   ├── workspace.go         # Output dir setup, session headers, lock
│   └── banner.go            # ASCII banner
├── internal/
│   ├── audit/               # Append-only audit log + secret redaction
│   ├── authgate/            # "I HAVE AUTHORIZATION" prompt
│   ├── config/              # YAML config parser, input validation
│   ├── executil/            # Process runner (Setpgid, context cancel)
│   ├── lock/                # OS flock + PID stale-lock detection
│   ├── logutil/             # Colourised + JSON logger
│   ├── notify/              # Best-effort webhook notifier
│   ├── pipeline/           # Engine, State, Phase interface
│   ├── phases/
│   │   ├── 01_subdomain/    # subfinder + assetfinder + crt.sh
│   │   ├── 02_httpx/        # httpx probe + CDN detection
│   │   ├── 03_portscan/     # naabu (top-1000 / full)
│   │   ├── 04_urldiscovery/ # gau/urlfinder/katana + URL dedup
│   │   ├── 05_secretscan/   # Worker pool JS fetch + secret regex
│   │   ├── 06_takeover/     # nuclei takeover templates
│   │   ├── 07_screenshots/  # gowitness
│   │   ├── 08_nuclei/       # nuclei vuln scan
│   │   ├── 09_burp/         # REST API active scan trigger
│   │   └── 10_report/       # summary.txt + summary.json
│   └── version/             # Build-time ldflags injection
├── go.mod
└── go.sum
```

---

## Testing

```bash
# Run all tests
go test ./... -count=1 -v

# Run tests for a specific package
go test ./internal/phases/04_urldiscovery/ -v

# Build and verify with dry-run
go build -o metsuke ./cmd/metsuke/
./metsuke -d example.com --dry-run
```

Key test suites:

| Package | What it covers |
|---|---|
| `internal/phases/01_subdomain/scope_test.go` | Anchored scope filter (v3 bug regression) |
| `internal/phases/04_urldiscovery/normalize_test.go` | URL normalization + dedup |
| `internal/phases/04_urldiscovery/sensitive_test.go` | Sensitive endpoint regex |
| `internal/phases/05_secretscan/patterns_test.go` | Secret pattern regex |
| `internal/config/` | Input validation (domain, threads, timeout, severity, regex) |
| `internal/audit/` | Secret redaction in audit log |
| `internal/authgate/` | Authorization prompt |
| `internal/lock/` | Single-instance lock + stale lock |
| `internal/executil/` | Process runner + timeout + context cancellation |

---

## Migration from bash (metsuke.sh)

See [MIGRATION.md](MIGRATION.md) for a detailed flag-by-flag mapping
from the bash version to the Go version, including config file format
changes and output file compatibility.

---

## Notes

- metsuke does **not** install any tools or modify your shell profile
  — install dependencies manually first.
- `--extended-workflows` and the JS secret scanner only ever issue
  passive `GET` requests, but they specifically hunt for endpoints and
  material that can disclose credentials — treat findings as sensitive
  and make sure your scope explicitly covers this kind of search.
- `--burp-active-scan` is the only phase in this pipeline that
  actively attacks endpoints. It is off by default and requires an
  explicit API key.
