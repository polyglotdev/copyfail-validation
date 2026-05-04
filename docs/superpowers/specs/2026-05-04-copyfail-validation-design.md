# Design: copyfail-validation v0.1 — AF_ALG-family Linux Kernel-Crypto Mitigation Validator

**Status:** Draft (pending user approval)
**Author:** Dom Hallan (dom@domhallan.com)
**Date:** 2026-05-04
**Repository:** github.com/polyglotdev/copyfail-validation
**Target version:** v0.1.0 (first public release)

## 1. Purpose

A static Go binary and reusable library that validates whether a Linux host has applied the defensive mitigations against AF_ALG-family kernel-crypto vulnerabilities — starting with copyfail (CVE-2026-31431) — and reports the result in formats consumable by Amazon SSM, security pipelines (SARIF), and Prometheus (textfile collector). Intended for fleet-wide compliance validation and operator-driven host audits, distributed via pkg.go.dev for both library consumers and direct CLI installation.

The tool is **defensive only**: it never attempts exploitation, never modifies host state, and only reads system information already accessible to a privileged operator.

## 2. Decisions Locked In

| Area | Decision | Rationale |
|---|---|---|
| Use case | SSM Run Command (primary) + general operator audit + pkg.go.dev library | Drives static binary, machine-readable output, library-first API design |
| Scope | AF_ALG-family validator with `copyfail` as the day-one preset | Avoids both single-CVE narrowness and unbounded "module validator" scope creep |
| Output formats | `human`, `json`, `sarif`, `prometheus` (textfile) | Covers operator UX, SSM aggregation, security pipelines, and Prometheus alerting |
| Distro support | RPM-based + DPKG-based (kernel/module checks distro-agnostic) | Covers ~95% of SSM-managed Linux fleets without over-engineering |
| Privilege model | Root-default, warn-and-skip if non-root | Matches SSM Agent's root execution while preserving developer ergonomics |
| Result states | `PASS`, `FAIL`, `SKIP`, `ERROR` | Distinguishes "not applicable" from "tool broke", maps cleanly to SARIF kinds |
| Project layout | Standard Go layout: public packages + `internal/` + `cmd/` | Matches `kubectl`, `gh`, `goreleaser`; allows free internal refactoring |
| License | Apache-2.0 | Patent grant matters for security tooling; enterprise-friendly |
| Logging | `log/slog` (stdlib) | Zero deps, JSON to stderr, structured per-check loggers |
| Tracing | OpenTelemetry, opt-in via `OTEL_EXPORTER_OTLP_ENDPOINT` | Off by default; available for SRE teams that want fleet-wide trace aggregation |

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  cmd/copyfail-validate (CLI, ~30 LOC main + flag parsing)           │
│   └─ parses flags ──► constructs Runner ──► picks Renderer ──► exit │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  preset/copyfail (public)                                           │
│   └─ exposes copyfail.All() []check.Check  ──► CVE-2026-31431       │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  check (public)                                                     │
│   ├─ type Check interface { Name, Description, Required,            │
│   │                          Applicable(ctx) bool, Run(ctx) Result }│
│   ├─ type Result { Name, State, Required, Detail, Evidence, … }     │
│   ├─ type State enum { Pass, Fail, Skip, Error }                    │
│   └─ Runner.Run(ctx, []Check) → Report                              │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  internal/  (private, refactor-freely)                              │
│   ├─ exec/      safe subprocess wrappers (no shell, allowlists)     │
│   ├─ kernelmod/ modprobe -nv, lsmod, /proc/modules parsing          │
│   ├─ integrity/ pkgmgr interface; rpm.go + dpkg.go backends         │
│   └─ render/    human/json/sarif/prom marshalers                    │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  report (public)                                                    │
│   └─ type Report { Host, Schema, Generated, Results, Summary }      │
│      with format constants + render.To(w, format) entry point       │
└─────────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Library first, CLI second.** The CLI is a thin frontend (~30 LOC `main` + flag wiring). Everything testable lives in importable packages.
2. **Public API minimalism.** Three public packages: `check`, `preset/copyfail`, `report`. Everything else is `internal/`. Refactor freely without breaking semver.
3. **Open/closed via interfaces.** New presets (future CVEs) implement `check.Check` and live under `preset/<name>/`. No core changes needed.
4. **Render-from-model.** One canonical `Report` struct → four format renderers. Adding a fifth format is a new file, not a refactor.
5. **Pluggable distro backend.** `integrity/pkgmgr.go` defines the interface; `rpm.go` and `dpkg.go` implement it; runtime auto-detection picks the right one. Same pattern as `database/sql` drivers.

### Non-goals (explicit YAGNI)

- No daemon mode in v0.1 (one-shot only).
- No `/metrics` HTTP endpoint (Prometheus textfile collector covers the use case).
- No remediation actions — read-only audit only. The tool *never* modifies host state.
- No support for Windows/macOS targets (Linux-host validator only; cross-builds are for *building* the binary on dev machines, not *running* it on those OSes).
- No exploitation code, ever. This is purely defensive validation.

### Project Layout

```
copyfail-validation/
├── check/                        # public: Check interface, Result, State enum
├── preset/
│   └── copyfail/                 # public: copyfail preset (the bundle)
├── report/                       # public: Report struct + format constants
├── internal/
│   ├── exec/                     # safe exec wrappers (no shell, allowlists)
│   ├── integrity/                # rpm + dpkg backends behind pkgmgr interface
│   ├── kernelmod/                # modprobe, lsmod, /proc parsers
│   ├── render/                   # human/json/sarif/prom marshalers
│   ├── hostinfo/                 # /etc/os-release, uname, hostname
│   ├── buildinfo/                # version/commit/build-date stamping
│   └── logging/                  # slog construction
├── cmd/
│   └── copyfail-validate/        # the CLI binary
├── docs/                         # design docs, runbooks, schema docs
├── examples/                     # importable Go example files (godoc)
├── schemas/                      # JSON schema files for report output
├── testdata/                     # shared real-world subprocess output samples
├── e2e/                          # Dockerfile per scenario; make e2e
├── .github/workflows/            # CI: test, lint, vuln-scan, release
├── .goreleaser.yaml
├── LICENSE                       # Apache-2.0
├── CHANGELOG.md                  # Keep-a-Changelog format
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── RELEASING.md
└── go.mod                        # currently go 1.26.2
```

## 4. Public API Surface

### Package `check`

```go
// Package check defines the Check interface and Result type used by all
// AF_ALG-family hardening validators. Implementations live in the preset/*
// packages; helpers live in internal/.
package check

type State string

const (
    StatePass  State = "pass"
    StateFail  State = "fail"
    StateSkip  State = "skip"
    StateError State = "error"
)

type Severity string

const (
    SeverityRequired Severity = "required"
    SeverityAdvisory Severity = "advisory"
)

type Check interface {
    ID() string                                                   // stable, machine-readable
    Title() string                                                // ≤80 chars
    Description() string                                          // SARIF rule.help.text
    Severity() Severity
    Applicable(ctx context.Context) (ok bool, reason string)
    Run(ctx context.Context) Result                               // MUST honor ctx, MUST NOT modify host state
}

type Result struct {
    CheckID    string         `json:"check_id"`
    Title      string         `json:"title"`
    State      State          `json:"state"`
    Severity   Severity       `json:"severity"`
    StartedAt  time.Time      `json:"started_at"`
    DurationMS int64          `json:"duration_ms"`
    Detail     string         `json:"detail,omitempty"`
    Evidence   map[string]any `json:"evidence,omitempty"`
    Err        string         `json:"error,omitempty"`           // present iff State==StateError
}

type Runner struct {
    Concurrency int           // 0 = NumCPU
    Timeout     time.Duration // per-check; 0 = 30s
    Logger      *slog.Logger  // nil disables
}

func (r *Runner) Run(ctx context.Context, checks []Check) report.Report
```

### Package `preset/copyfail`

```go
// Package copyfail provides the validator preset for CVE-2026-31431
// ("copyfail"), an AF_ALG-family Linux kernel-crypto vulnerability.
package copyfail

const CVE = "CVE-2026-31431"

// All returns the full list of checks for the copyfail mitigation posture.
func All() []check.Check
```

### Package `report`

```go
// Package report defines the canonical Report aggregate and the format
// constants used by the renderers.
package report

type Format string

const (
    FormatHuman      Format = "human"
    FormatJSON       Format = "json"
    FormatSARIF      Format = "sarif"
    FormatPrometheus Format = "prometheus"
)

type Report struct {
    SchemaVersion string         `json:"schema_version"` // semver of this struct, independent of tool version
    Tool          ToolInfo       `json:"tool"`
    Host          HostInfo       `json:"host"`
    Generated     time.Time      `json:"generated_at"`
    Results       []check.Result `json:"results"`
    Summary       Summary        `json:"summary"`
}

type ToolInfo struct {
    Name      string `json:"name"`
    Version   string `json:"version"`
    Commit    string `json:"commit"`
    BuildDate string `json:"build_date"`
}

type HostInfo struct {
    Hostname      string `json:"hostname"`
    KernelRelease string `json:"kernel_release"`
    OSRelease     string `json:"os_release"`
    OSVersion     string `json:"os_version_id"`
    Arch          string `json:"arch"`
}

type Summary struct {
    Total    int    `json:"total"`
    Pass     int    `json:"pass"`
    Fail     int    `json:"fail"`
    Skip     int    `json:"skip"`
    Error    int    `json:"error"`
    Required Bucket `json:"required"`
}

type Bucket struct {
    Pass int `json:"pass"`
    Fail int `json:"fail"`
}

// WriteTo writes the report to w in the given format.
func (rep Report) WriteTo(w io.Writer, f Format) (int64, error)
```

### CLI flags (cmd/copyfail-validate)

```
copyfail-validate [flags]

Flags:
  --format string         Output format: human|json|sarif|prometheus (default "human" on TTY, "json" otherwise)
  --output string         Output path; "-" for stdout (default "-")
  --timeout duration      Per-check timeout (default 30s)
  --concurrency int       Max parallel checks (default NumCPU)
  --module string         Override module name to validate (default "algif_aead")
  --conf string           Override modprobe.d path (default "/etc/modprobe.d/disable-algif-aead.conf")
  --skip strings          Comma-separated check IDs to skip
  --only strings          Comma-separated check IDs to run exclusively
  --sign                  Write report.json.sha256 alongside output
  --no-color              Disable ANSI colors (also honored: NO_COLOR env)
  --verbose, -v           Increase logging verbosity (count: -v=info, -vv=debug)
  --version               Print version and exit
  --help, -h              Print help and exit

Environment variables (lowest precedence):
  COPYFAIL_FORMAT, COPYFAIL_TIMEOUT, COPYFAIL_MODULE, COPYFAIL_CONF
  OTEL_EXPORTER_OTLP_ENDPOINT (enables tracing if set)
```

## 5. Data Flow & Result Lifecycle

### End-to-end flow

```
                  ┌─────────────────────────────┐
   exec start ──► │ cmd/copyfail-validate/main  │
                  └──────────────┬──────────────┘
                                 │ 1. parse flags + env
                                 │ 2. detect TTY → pick default format
                                 │ 3. construct context.WithSignals (SIGINT/SIGTERM)
                                 ▼
                  ┌─────────────────────────────┐
                  │ buildinfo + hostinfo gather │
                  └──────────────┬──────────────┘
                                 │
                                 ▼
                  ┌─────────────────────────────┐
                  │ preset/copyfail.All()       │
                  └──────────────┬──────────────┘
                                 │ filter via --skip / --only
                                 ▼
                  ┌─────────────────────────────┐
                  │ check.Runner.Run(ctx,…)     │
                  │  for each Check (parallel): │
                  │    Applicable(ctx)?         │
                  │      no  → Skip             │
                  │      yes → WithTimeout      │
                  │            Run(ctx)         │
                  │            recover()→Error  │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │ assemble report.Report      │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │ rep.WriteTo(w, format)      │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │ exit code from Summary      │
                  └─────────────────────────────┘
```

### Concurrency model

- `Runner` runs checks in a bounded worker pool (`Concurrency`, default `runtime.NumCPU()`).
- Each check gets its own `context.WithTimeout(parent, Timeout)`.
- Results assembled in **stable, deterministic order** matching `[]Check` input order — diff-friendly across runs.
- Total run bounded by parent context (CLI hooks `SIGINT`/`SIGTERM`); on cancellation, in-flight checks return `StateError` with `ctx.Err()`.

### State Semantics — concrete examples

| Scenario | State | Why |
|---|---|---|
| `algif_aead` in `/proc/modules` | **Fail** | Mitigation requires module not loaded |
| `/etc/modprobe.d/disable-algif-aead.conf` missing | **Fail** | Required mitigation absent |
| `modprobe` binary not in `$PATH` | **Error** | Could not perform the check |
| `rpm -V` shows mtime delta but matching hash | **Pass** with note in evidence | Hash match is what matters |
| `rpm -V` shows hash mismatch | **Fail** (advisory) | Possible binary tamper |
| `dpkg`-based host hits the `rpm` integrity check | **Skip** with reason | The dpkg sibling check covers it |
| Non-root user runs `lsof`-based AF_ALG check | **Skip** with `reason="requires root"` | Documented degradation |
| Check panics due to a bug | **Error** with stack trace logged | Bugs surface loudly, no crash |
| Check exceeds timeout | **Error** with `Err: "deadline exceeded"` | Operator can raise `--timeout` |

### Evidence shapes

```jsonc
// modprobe dry-run check
"evidence": {
  "command": "modprobe -n -v algif_aead",
  "stdout": "install /bin/false ",
  "exit_code": 0,
  "matched_directive": "install /bin/false"
}

// integrity check
"evidence": {
  "backend": "rpm",
  "package": "util-linux-core-2.39.4-7.amzn2023.x86_64",
  "verify_output": "",
  "path": "/usr/bin/su"
}

// kernel module loaded check
"evidence": {
  "source": "/proc/modules",
  "matched_line": "algif_aead 16384 0 - Live 0xffffffff..."
}
```

### Schema versioning

- `report.SchemaVersion` is a separate semver from the tool version.
- v0.1 ships `"schema_version": "1.0.0"`.
- Optional fields = no bump. Renaming/removing = major. Required-field additions = minor.
- Documented in `docs/schema.md`; validated in CI against `schemas/report-1.0.0.json`.

## 6. Error Handling & Exit Codes

### Exit code contract (frozen at v1.0.0)

| Code | Meaning |
|---|---|
| **0** | All required checks passed (advisory failures, skips, check-level errors tolerated) |
| **2** | At least one required check returned `StateFail` |
| **3** | Tool-level error (cannot read flags, write output, detect host) before any check ran |
| **4** | Check-level errors only, no required failures — surfaces "we couldn't fully validate" |
| **64** | Usage error (`EX_USAGE`): bad flag, unknown `--format`, conflicting `--only`/`--skip` |
| **130** | Interrupted by SIGINT |
| **143** | Interrupted by SIGTERM |

### Internal error handling philosophy

1. **Wrap with `%w`, never lose context.** All internal errors wrap the underlying error; callers can `errors.Is`/`errors.As`.
2. **Sentinel errors at package boundaries.** `internal/exec` exports `ErrCommandNotFound`, `ErrTimeout`. Higher layers translate to user-facing `Detail` strings.
3. **Panics are bugs, never control flow.** `Runner.Run` worker `recover()`s panics, marks result `StateError`, logs stack trace, continues. Binary never crashes mid-run.

### Output stream discipline

- **stdout:** ONLY the report in the chosen format. Nothing else, ever.
- **stderr:** All log lines, warnings, error messages.
- Enforced in tests: JSON output asserts `bytes.Equal(stdout, json.Marshal(report))` byte-for-byte.

## 7. Security Model

### Threat model — defended against

| Threat | Mitigation |
|---|---|
| Shell injection via configurable input (current code is vulnerable) | Eliminate `sh -c` entirely. Parse output in Go. Allowlist regex on flag/env input. |
| Path traversal via `--conf` flag | `filepath.Clean` + check resolved path is under `/etc/modprobe.d/` (configurable). Symlinks logged in `Evidence`. |
| Argument injection to subprocesses | Separate args (`exec.Command("rpm", "-V", pkgName)`). Reject `\x00`, leading `-`, shell metacharacters in untrusted args. |
| Subprocess hijack via `$PATH` | `internal/exec` resolves binaries against allowlist of absolute paths with `LookPath` fallback. Resolved path logged in `Evidence["resolved_command"]`. |
| Symlink race / TOCTOU on conf files | `O_NOFOLLOW` for files expected to be regular. Explicit stat + log target if symlink allowed. |
| Resource exhaustion (subprocess hangs) | Every subprocess under `context.WithTimeout`. SIGTERM, then SIGKILL after 2s. |
| Output truncation attacks | Captured stdout/stderr bounded to 1 MiB per command. Excess dropped with marker. |
| Supply chain compromise | See "Supply chain" below. |
| Sensitive data in output | Hostnames included (necessary). No MAC/machine-id/IP/users unless `--include-host-detail`. `redact()` strips `password\|token\|secret\|bearer` patterns from evidence. |

### Out of scope

- Root attacker on the host. Documented in `SECURITY.md` — we are a compliance reporter, not an EDR.
- Kernel-level evasion. Same reasoning.
- Adversarial local users. Tool is meant for root or SSM Agent.

### `internal/exec` — safe subprocess wrapper

```go
package exec // internal

type Cmd struct {
    Name    string        // logical name, not path
    Args    []string      // each validated against allowedArgRE
    Timeout time.Duration // default 30s
    Env     []string      // default minimal: PATH, LANG=C
}

type Result struct {
    Stdout   []byte // bounded to 1 MiB
    Stderr   []byte
    ExitCode int
    Path     string // resolved absolute path of executable
    Duration time.Duration
}

var allowedCommands = map[string]string{
    "modprobe": "/sbin/modprobe",
    "lsmod":    "/sbin/lsmod",
    "uname":    "/bin/uname",
    "rpm":      "/usr/bin/rpm",
    "dpkg":     "/usr/bin/dpkg",
    "debsums":  "/usr/bin/debsums",
    "lsof":     "/usr/bin/lsof",
}

var allowedArgRE = regexp.MustCompile(`^[A-Za-z0-9._\-/+:=,@]*$`)

func (c Cmd) Run(ctx context.Context) (Result, error)
```

Properties:
- **No shell.** Never call `sh`, `bash`, or `system()`.
- **Allowlisted commands.** Non-allowlisted → `ErrCommandDenied`.
- **Allowlisted argument character set.** Untrusted input must pass `allowedArgRE`. `Trusted("…")` type bypasses for known-safe values.
- **Minimal environment.** `LANG=C` for parser determinism. `PATH` for `LookPath`. Nothing else by default.

### Supply chain security

| Control | Implementation |
|---|---|
| Reproducible builds | GoReleaser + `-trimpath`, `-buildvcs=true`, `-ldflags="-s -w -X …Version=…"` |
| Build provenance | GitHub Actions OIDC + `slsa-github-generator` → SLSA Level 3 |
| Sigstore signatures | `cosign sign-blob --keyless` on every release artifact |
| SBOM | `syft` SPDX + CycloneDX per arch, per release |
| Vulnerability scanning | `govulncheck` per PR (blocks merge), `osv-scanner` nightly, `trivy fs` for secrets |
| Dependency posture | Strong stdlib preference; non-stdlib deps justified in `docs/dependencies.md` |
| Auto-updates | Renovate/Dependabot with auto-merge for security patches after CI |
| Tag signing | GPG-signed tags; documented in `RELEASING.md` |
| `go.sum` discipline | `go mod tidy` in CI; PRs touching `go.sum` without `go.mod` flagged |
| Disclosure policy | `SECURITY.md`, PGP contact, 90-day window per CERT/CC guidelines |

### Static analysis in CI (all block merge)

```
gosec -severity=medium -confidence=medium ./...
golangci-lint run --enable=gosec,govet,staticcheck,errcheck,bodyclose,gocritic,revive
govulncheck ./...
go test -race ./...
```

## 8. Observability

### 1. Structured logging — `log/slog` only

- JSON to **stderr**, always. Human-format reports keep stdout clean for `jq`.
- `run_id` UUID baked into every log line (per-run correlation across fleet).
- Per-check child loggers via `slog.With("check_id", c.ID())`.
- Sensitive structs implement `slog.LogValuer` to control logged fields.
- Verbosity: `-v`=info, `-vv`=debug; `AddSource` only at debug.

### 2. Fleet-wide metrics — Prometheus textfile collector

Exposition format example:

```
# HELP copyfail_validator_check_state Result of one mitigation check (1 = current state).
# TYPE copyfail_validator_check_state gauge
copyfail_validator_check_state{check_id="modprobe.dry_run",severity="required",state="pass"} 1
copyfail_validator_check_state{check_id="modprobe.dry_run",severity="required",state="fail"} 0

# HELP copyfail_validator_check_duration_seconds Time spent running each check.
# TYPE copyfail_validator_check_duration_seconds gauge
copyfail_validator_check_duration_seconds{check_id="modprobe.dry_run"} 0.018

# HELP copyfail_validator_summary Summary of last validation run.
# TYPE copyfail_validator_summary gauge
copyfail_validator_summary{outcome="pass"} 6
copyfail_validator_summary{outcome="fail"} 0

# HELP copyfail_validator_required_failures Required-check failures (drives paging).
# TYPE copyfail_validator_required_failures gauge
copyfail_validator_required_failures 0

# HELP copyfail_validator_last_run_timestamp_seconds Unix time of last successful run.
# TYPE copyfail_validator_last_run_timestamp_seconds gauge
copyfail_validator_last_run_timestamp_seconds 1762267800

# HELP copyfail_validator_build_info Build info as labels.
# TYPE copyfail_validator_build_info gauge
copyfail_validator_build_info{version="v0.1.0",commit="abc1234",go_version="go1.26.2"} 1
```

Suggested alerting rule:

```
alert: CopyfailMitigationGap
expr: max by (instance) (copyfail_validator_required_failures) > 0
for: 10m
```

**Atomic write protocol** for `.prom` files (consumer reads partial files otherwise):
```go
func writeTextfileAtomic(dir, name string, data []byte) error {
    tmp, err := os.CreateTemp(dir, name+".tmp.*")
    if err != nil { return err }
    if _, err := tmp.Write(data); err != nil { tmp.Close(); return err }
    if err := tmp.Sync(); err != nil { tmp.Close(); return err }
    if err := tmp.Close(); err != nil { return err }
    return os.Rename(tmp.Name(), filepath.Join(dir, name+".prom"))
}
```

### 3. Tracing — opt-in OpenTelemetry

- Off by default; zero overhead, zero deps loaded.
- Enabled by `OTEL_EXPORTER_OTLP_ENDPOINT` env var (matches OTel auto-config convention).
- One root span per run (`copyfail-validate.run`) with attributes: `tool.version`, `host.name`, `host.os.id`, `host.kernel.release`, `summary.fail`, `summary.required_failures`. Exit code mapped to span status.
- One child span per check (`copyfail-validate.check`) with attributes `check.id`, `check.state`, `check.severity`, `check.duration_ms`.

### 4. Audit trail / evidence preservation

- All times in RFC3339 with timezone offset.
- Tool version + commit baked into every report via ldflags.
- Optional canonical hashing: `--sign` writes `<output>.sha256` alongside report (canonical-JSON SHA-256). Operator can countersign with their own KMS/cosign workflow.

### Deliberately not included

- No `/metrics` HTTP endpoint (one-shot, not a daemon).
- No log shipping (stderr → wherever SSM/journald/CloudWatch already collects it).
- No remote config / phone-home.

## 9. Testing Strategy

### Coverage targets

- ≥85% for `check/`, `report/`, `internal/*`
- ≥95% for `internal/exec` and `internal/render` (highest-risk, most-imported)

### Test pyramid

```
                    ▲
                   ╱ ╲
                  ╱E2E╲              ~5 tests, real distros (Docker)
                 ╱─────╲
                ╱  CLI  ╲             ~15 tests, exec built binary
               ╱─────────╲
              ╱Integration╲           ~30 tests, real exec + tmpdir, no network
             ╱─────────────╲
            ╱      Unit     ╲         ~150 tests, table-driven, no I/O
           ╱─────────────────╲
          ╱   Fuzz   │   Race ╲       continuous, parsers + concurrency
         ▼───────────────────────▼
```

### Conventions enforced everywhere

- `t.Parallel()` on every test.
- `t.TempDir()` for filesystem fixtures (auto-cleanup).
- `cmp.Diff` from `github.com/google/go-cmp` (only non-stdlib test dep).
- Sentinel errors compared with `errors.Is`, never string-matched.

### `Runner` interface — testability without a mocking framework

```go
// internal/exec
type Runner interface {
    Run(ctx context.Context, cmd Cmd) (Result, error)
}
type osRunner struct{}                                    // production
type FakeRunner struct {
    Responses map[string]Result                            // tests
    Calls     []Cmd
}
```

Each check accepts `Runner` via constructor injection. Production wires `osRunner{}`; tests wire `FakeRunner`. **No mocking framework needed.** For testing `osRunner` itself, use the `TestHelperProcess` pattern from `os/exec`'s own tests.

### Integration tests

- `//go:build linux` + `//go:build integration` build tag.
- `requireBinary(t, "modprobe")` skip helper.
- `t.TempDir()` populated with fake `/etc/modprobe.d/` files (golden + corrupted variants).
- Zero network.
- Run via `go test -tags=integration ./...`.

### CLI tests

Under `cmd/copyfail-validate/main_test.go`:
- Binary built once per `TestMain` via `sync.Once`-cached path.
- Per-format tests: `--format=json` parseable, `--format=sarif` schema-valid, `--format=prometheus` parseable by `expfmt.TextParser`, `--format=human` golden-file matched.
- Exit code tests: 0/2/3/4/64/130/143 each have a triggering scenario.
- SIGTERM mid-run produces 143 + valid partial JSON.

### End-to-end tests

- `e2e/` directory with one `Dockerfile` per scenario.
- AL2023 with mitigation correct → exit 0 + all `pass`.
- Ubuntu 22.04 unmitigated → exit 2 + `dpkg` backend selected.
- Rocky 9 with conf present but module loaded (drift) → exit 2 + specific check IDs failing.
- `make e2e` builds + mounts + asserts.
- CI runs on `push: main` only (slow).

### Fuzz tests — parsers only

```go
func FuzzParseProcModules(f *testing.F) {
    f.Add("ext4 901120 1 - Live 0xffffffffc0a00000\n")
    f.Add("")
    f.Fuzz(func(t *testing.T, in string) {
        _, _ = kernelmod.ParseProcModules(strings.NewReader(in))
        // assertion: never panics, never blocks
    })
}
```

Same for `lsmod`, `modprobe -nv`, `rpm -V`, `dpkg -S`, `/etc/os-release`. 30s per fuzzer in CI; corpora persist in `testdata/fuzz/`.

### Race detector + benchmarks

- `go test -race ./...` per PR.
- `benchstat` on PRs touching `internal/kernelmod` or `internal/exec`. Baseline at `testdata/benchstat-baseline.txt`.

### CI matrix

```yaml
strategy:
  matrix:
    go: ["1.26.x", "stable"]
    os: [ubuntu-22.04, ubuntu-24.04]
steps:
  - go test -race -coverprofile=cover.out ./...
  - go test -tags=integration ./...
  - golangci-lint run
  - gosec -severity=medium ./...
  - govulncheck ./...
  - go test -fuzz=. -fuzztime=30s ./internal/kernelmod
```

E2E job runs separately on `push: main`.

### Test data discipline

- Real-world output samples under `testdata/` with provenance documented in `testdata/README.md` (anonymized: hostnames stripped, addresses zeroed).
- Golden files for human-format output; `cmp.Diff` shows exact deltas.
- `-update` flag regenerates golden files when output intentionally changes.

## 10. Distribution & Release

### License

**Apache License 2.0**, full text at `/LICENSE`. Per-file SPDX header:
```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0
```

### Module path & versioning

- Repo: `github.com/polyglotdev/copyfail-validation`
- Module path matches.
- CLI binary: `copyfail-validate`.
- v2+ rule: module path becomes `…/v2` per Go import compatibility.

### Semver discipline

| Change | Bump |
|---|---|
| New check in `preset/copyfail` | Patch |
| New public function/method | Minor |
| New optional field in `report.Report` | Minor |
| Removing/renaming exported symbol | Major |
| Changing exit code semantics | Major |
| Bumping `Report.SchemaVersion` major | Major |

Hold at `v0.x.y` until at least one external consumer cycle. First public release: **v0.1.0**. First stable: **v1.0.0** after ≥4 weeks at v0.x with no breaking changes.

### Release pipeline

`.goreleaser.yaml` produces per release tag:
- Static binaries: `linux/amd64`, `linux/arm64` with `-trimpath -ldflags="-s -w -X …"`.
- `tar.gz` archives with `LICENSE`, `README.md`, `CHANGELOG.md`.
- `checksums.txt` (SHA-256) + cosign signature.
- SBOMs (SPDX + CycloneDX) per archive.
- DEB / RPM / APK packages via nfpm.
- Distroless container image to `ghcr.io/polyglotdev/copyfail-validation`.

CI workflows:
- `test.yml` — every PR: tests, race, lint, vuln scan, fuzz 30s.
- `release.yml` — on tag `v*`: GoReleaser + `slsa-github-generator` (SLSA L3 provenance) + GitHub Release.
- `scorecard.yml` — weekly OpenSSF Scorecard.
- `codeql.yml` — GitHub-native SAST.

### Distribution channels (day one)

| Channel | Audience |
|---|---|
| GitHub Releases | Primary binary distribution |
| pkg.go.dev | Library consumers |
| `go install` | Devs wanting latest CLI |
| Container image (`ghcr.io`) | Kubernetes/ECS/sidecar |
| DEB/RPM/APK | Operators using package managers |

Homebrew + AUR can come post-v1.0.

### Documentation deliverables (pkg.go.dev requirements)

- Every exported symbol: godoc starting with the symbol name, complete sentence, explains *purpose*.
- Per-package `doc.go` for the pkg.go.dev landing page.
- Runnable `Example_*` tests per public package.

Required top-level docs:

| File | Purpose |
|---|---|
| `README.md` | Hero, quick-start, badges, links |
| `LICENSE` | Apache-2.0 full text |
| `CHANGELOG.md` | Keep-a-Changelog format |
| `SECURITY.md` | Coordinated-disclosure policy, PGP contact |
| `CONTRIBUTING.md` | PR guidelines, DCO sign-off, dev setup |
| `CODE_OF_CONDUCT.md` | Contributor Covenant 2.1 |
| `RELEASING.md` | Maintainer release runbook |
| `docs/checks.md` | Catalog of every check ID with description, severity, evidence shape |
| `docs/schema.md` | JSON output schema + `schema_version` compatibility contract |
| `docs/runbook-ssm.md` | Copy-paste SSM Document examples for AL2/AL2023/Ubuntu |
| `docs/runbook-prometheus.md` | Cron + textfile collector + alerting rule examples |

### CHANGELOG entry shape (committed from day 1)

```markdown
## [Unreleased]

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security
```

### Initial-release checklist (gate before tagging v0.1.0)

- [ ] All public symbols have godoc.
- [ ] At least one `Example_*` test per public package.
- [ ] `LICENSE`, `README.md`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md` present.
- [ ] CI green: tests, race, lint, gosec, govulncheck, fuzz.
- [ ] `goreleaser release --snapshot --clean` succeeds locally.
- [ ] `go install github.com/polyglotdev/copyfail-validation/cmd/copyfail-validate@HEAD` works on a clean GOPATH.
- [ ] Manually run on AL2023, Ubuntu 22.04, and a known-vulnerable test container; outputs match expected.
- [ ] Tag is GPG-signed.
- [ ] Release notes link to first-time-user docs.

## 11. Day-One Check Catalog (preset/copyfail)

The `copyfail.All()` bundle ships the following checks for v0.1.0. Each maps 1:1 to a `Check` implementation.

| ID | Title | Severity | Applicable | Detail |
|---|---|---|---|---|
| `kernel.version` | Kernel release reported | advisory | always | Informational; populates `host.kernel_release` |
| `modprobe.conf_present` | Modprobe blocklist file present | required | always | `/etc/modprobe.d/disable-algif-aead.conf` exists |
| `modprobe.conf_correct` | Blocklist contains both `install … /bin/false` and `blacklist …` | required | always | Both directives present |
| `modprobe.dry_run` | `modprobe -n -v` resolves to `/bin/false` | required | requires `modprobe` binary | Confirms runtime block |
| `module.not_loaded` | Target module absent from `/proc/modules` | required | always | Parses `/proc/modules` directly (no shell) |
| `afalg.no_active_users` | No process holds an `AF_ALG` socket | advisory | requires root + `lsof` | Best-effort detection |
| `integrity.su_binary` | `/usr/bin/su` matches package manager records | advisory | `rpm` or `dpkg` present | Backend auto-selected |
| `hostinfo.os_release` | `/etc/os-release` parseable | advisory | always | Populates `host.os_release` / `host.os_version_id` |

The current code's checks 1–6 are preserved (with `module.not_loaded` migrated off `sh -c`). Checks added relative to today's code: `modprobe.conf_present` is split out from `modprobe.conf_correct` for clearer reporting; `kernel.version` and `hostinfo.os_release` become explicit checks rather than implicit fields.

## 12. Open Questions / Future Work

- **Additional presets.** When the next AF_ALG-family CVE drops, add `preset/<name>/` and document in `docs/checks.md`. No core changes expected.
- **Aarch64 / arm64 testing.** GoReleaser produces arm64 binaries; CI E2E currently amd64-only. Add arm64 GitHub Actions runner once available in the budget.
- **Drift detection (post-v1.0).** A `--baseline=<path>` flag to compare current output against a stored baseline. Out of scope for v0.1.
- **Plugin model (post-v1.0).** Loading external `Check` implementations via Go plugins. Likely never — too fragile in Go's plugin system; presets-as-imports is the recommended extension model.
- **Localization.** All human-format output is en-US. No plans to localize; SARIF/JSON/Prometheus are language-neutral.

## 13. References

- CVE-2026-31431 (copyfail) — primary motivation
- Linux kernel `algif_aead` module documentation
- [SARIF v2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
- [Prometheus textfile collector](https://github.com/prometheus/node_exporter#textfile-collector)
- [Keep a Changelog](https://keepachangelog.com/)
- [SLSA Build Level 3](https://slsa.dev/spec/v1.0/levels#build-l3)
- [Google Go Style Guide — Best Practices](https://google.github.io/styleguide/go/best-practices.html)
- [Go Module Reference — import compatibility rule](https://research.swtch.com/vgo-import)
- [OWASP Top 10 — Software & Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
