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
│   ├─ type Check interface { ID, Title, Description, Severity,       │
│   │                          Applicable(ctx) (bool,string),         │
│   │                          Run(ctx) report.Result }               │
│   └─ Runner.Run(ctx, []Check) → report.Report                       │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  internal/  (private, refactor-freely)                              │
│   ├─ exec/      safe subprocess wrappers (no shell, Trusted args)   │
│   ├─ kernelmod/ modprobe -nv, /proc/modules, /etc/modprobe.d parser │
│   ├─ procscan/  /proc/<pid>/{fd,maps,comm} scanner (afalg users)    │
│   ├─ integrity/ pkgmgr interface; rpm.go + dpkg.go backends         │
│   ├─ redact/    secret-pattern redactor for Evidence/Detail         │
│   ├─ canonjson/ RFC 8785 (JCS) canonicalizer for --sign sidecar     │
│   └─ render/    human/json/sarif/prom marshalers                    │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  report (public, LEAF — imports nothing in this module)             │
│   ├─ type State enum { Pass, Fail, Skip, Error }                    │
│   ├─ type Severity enum { Required, Advisory }                      │
│   ├─ type Result { CheckID, State, Severity, Detail, Evidence, … } │
│   └─ type Report { Tool, Host, Generated, Results, Summary }        │
│       + Format consts + WriteTo(w, Format)                          │
└─────────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Library first, CLI second.** The CLI is a thin frontend (~30 LOC `main` + flag wiring). Everything testable lives in importable packages.
2. **Public API minimalism.** Three public packages: `report` (data, leaf), `check` (behavior, imports `report`), `preset/copyfail` (the bundle, imports both). Everything else is `internal/`. Refactor freely without breaking semver.
3. **One-directional package graph.** `report` is the leaf — it imports no other package in this module. `check` imports `report`. `preset/*` imports `check` and `report`. `internal/*` may import any public package and any other `internal/*`. Enforced in CI via `golangci-lint`'s `depguard` rule (`.golangci.yml`): a deny rule on the `report` package forbids importing `github.com/polyglotdev/copyfail-validation/check`, `…/preset/...`, or `…/internal/...`. The lint failure message points the offender to this section of the spec.
4. **Open/closed via interfaces.** New presets (future CVEs) implement `check.Check` and live under `preset/<name>/`. No core changes needed.
5. **Render-from-model.** One canonical `report.Report` struct → four format renderers. Adding a fifth format is a new file, not a refactor.
6. **Pluggable distro backend.** `internal/integrity/pkgmgr.go` defines the interface; `rpm.go` and `dpkg.go` implement it; `Detect()` picks one at runtime. Same pattern as `database/sql` drivers.

### Non-goals (explicit YAGNI)

- No daemon mode in v0.1 (one-shot only).
- No `/metrics` HTTP endpoint (Prometheus textfile collector covers the use case).
- No remediation actions — read-only audit only. The tool *never* modifies host state.
- No support for Windows/macOS targets (Linux-host validator only; cross-builds are for *building* the binary on dev machines, not *running* it on those OSes).
- No exploitation code, ever. This is purely defensive validation.

### Project Layout

```
copyfail-validation/
├── report/                       # public: Report, Result, State, Severity, Format (LEAF — imports nothing in this module)
├── check/                        # public: Check interface, Runner (imports report)
├── preset/
│   └── copyfail/                 # public: copyfail.All() bundle (imports check + report)
├── internal/
│   ├── exec/                     # safe exec wrappers (no shell, allowlists, Trusted/Untrusted typing)
│   ├── integrity/                # rpm + dpkg backends behind pkgmgr interface; Detect() chooses one
│   ├── kernelmod/                # modprobe, lsmod, /proc/modules, /etc/modprobe.d/* parsers
│   ├── procscan/                 # /proc/<pid>/{fd,maps,comm} scanner for afalg.no_active_users
│   ├── render/                   # human/json/sarif/prom marshalers; one file per format
│   ├── hostinfo/                 # /etc/os-release, uname, hostname
│   ├── redact/                   # secret-pattern redactor used before any string lands in Evidence/Detail
│   ├── buildinfo/                # version/commit/build-date stamping (set via -ldflags)
│   ├── canonjson/                # RFC 8785 (JCS) canonicalizer for the --sign sidecar
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

### Package layering rule (avoids import cycle)

**Data downstream, behavior upstream.** Value types (`State`, `Severity`, `Result`, `Report`, `Format`, `Summary`, etc.) live in `report`. Behavior types (`Check` interface, `Runner`) live in `check`. `check` imports `report`; `report` imports nothing in this module. This matches stdlib (`net/http` imports `net/url`, never the reverse) and eliminates the cycle a naive split would create.

### Package `check`

```go
// Package check defines the Check interface and the Runner that executes
// a slice of Checks. Result data structures live in the report package
// to keep this package's import graph one-directional.
package check

import (
    "context"
    "log/slog"
    "time"

    "github.com/polyglotdev/copyfail-validation/report"
)

// Check is the unit of validation. Implementations must be pure (no global
// state) and safe to call concurrently with other Checks. Implementations
// MUST NOT modify host state.
type Check interface {
    ID() string                                                   // stable, machine-readable; appears in JSON, SARIF rule IDs, Prometheus labels
    Title() string                                                // ≤80 chars
    Description() string                                          // long-form, SARIF rule.help.text
    Severity() report.Severity
    Applicable(ctx context.Context) (ok bool, reason string)
    Run(ctx context.Context) report.Result                        // MUST honor ctx
}

// Runner executes a slice of Checks and produces a report.Report.
type Runner struct {
    Concurrency int           // max parallel checks; 0 = runtime.NumCPU()
    Timeout     time.Duration // per-check; 0 = 30s
    Logger      *slog.Logger  // nil disables
}

// Run executes the checks and returns the assembled Report. The order of
// Report.Results is guaranteed to match the order of the input slice
// (diff-friendly across runs). Cancelling ctx cancels all in-flight checks.
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
// Package report defines the canonical Report aggregate, the value types
// (State, Severity, Result), and the output Format constants. This package
// imports nothing within this module — it is the leaf of the dependency
// graph so that check, preset, render and cmd may all import it freely
// without creating cycles.
package report

import (
    "io"
    "time"
)

// State is the outcome of running a Check.
//
// SARIF mapping (used by the SARIF renderer):
//
//	StatePass  → "pass"
//	StateFail  → "fail"
//	StateSkip  → "notApplicable"
//	StateError → "open"          // runtime kind: result not available
type State string

const (
    StatePass  State = "pass"
    StateFail  State = "fail"
    StateSkip  State = "skip"
    StateError State = "error"
)

// Severity classifies the operational meaning of a failed check.
// A failed Required check produces a non-zero process exit; a failed
// Advisory check is reported but does not change the exit code.
type Severity string

const (
    SeverityRequired Severity = "required"
    SeverityAdvisory Severity = "advisory"
)

// Format is one of the supported renderer outputs.
type Format string

const (
    FormatHuman      Format = "human"
    FormatJSON       Format = "json"
    FormatSARIF      Format = "sarif"
    FormatPrometheus Format = "prometheus"
)

// Result is the outcome of one Check execution.
type Result struct {
    CheckID    string         `json:"check_id"`
    Title      string         `json:"title"`
    State      State          `json:"state"`
    Severity   Severity       `json:"severity"`
    StartedAt  time.Time      `json:"started_at"`           // RFC3339 with offset on the wire
    DurationMS int64          `json:"duration_ms"`
    Detail     string         `json:"detail,omitempty"`     // operator-readable one-liner
    Evidence   map[string]any `json:"evidence,omitempty"`   // structured artifacts; see §11 per-check shapes
    Err        string         `json:"error,omitempty"`      // non-empty iff State == StateError
}

// Report is the canonical aggregate of a single validator run.
type Report struct {
    SchemaVersion string    `json:"schema_version"` // semver of THIS struct, independent of tool version
    Tool          ToolInfo  `json:"tool"`
    Host          HostInfo  `json:"host"`
    Generated     time.Time `json:"generated_at"`
    Results       []Result  `json:"results"`        // stable order matching Runner input
    Summary       Summary   `json:"summary"`
}

type ToolInfo struct {
    Name      string `json:"name"`
    Version   string `json:"version"`     // semver, set at build time via -ldflags
    Commit    string `json:"commit"`      // short git sha
    BuildDate string `json:"build_date"`  // RFC3339
}

type HostInfo struct {
    Hostname      string `json:"hostname"`
    KernelRelease string `json:"kernel_release"`
    OSRelease     string `json:"os_release"`     // ID from /etc/os-release
    OSVersion     string `json:"os_version_id"`  // VERSION_ID from /etc/os-release
    Arch          string `json:"arch"`
}

type Summary struct {
    Total    int    `json:"total"`
    Pass     int    `json:"pass"`
    Fail     int    `json:"fail"`
    Skip     int    `json:"skip"`
    Error    int    `json:"error"`
    Required Bucket `json:"required"` // breakdown for required-only outcomes
}

type Bucket struct {
    Pass  int `json:"pass"`
    Fail  int `json:"fail"`
    Error int `json:"error"`
}

// WriteTo writes the report to w in the given format. It satisfies io.WriterTo
// when called with a fixed format via a closure; the (w, f) signature is kept
// here for direct CLI use. Implementation lives in internal/render.
func (rep Report) WriteTo(w io.Writer, f Format) (int64, error)
```

**Note on `Bucket`:** Required outcomes track `Pass`, `Fail`, **and** `Error` (added in this revision) so callers can compute the exit code purely from the Summary without re-iterating Results. See §6.

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
| `algif_aead` in `/proc/modules` | **Fail** (required) | Mitigation requires module not loaded |
| `/etc/modprobe.d/disable-algif-aead.conf` missing | **Fail** (required) | Required mitigation absent |
| `modprobe` binary not in `$PATH` and check is required | **Error** (required) → contributes to exit code 4 | Could not perform a check we needed to perform; see §6 priority rules |
| `rpm -V` shows mtime delta but matching hash | **Pass** with mtime delta noted in `Evidence` | Hash match is what matters |
| `rpm -V` shows hash mismatch | **Fail** (advisory) | Possible binary tamper |
| Host has neither `rpm` nor `dpkg` (e.g., minimal container, source-built distro) | **Skip** with `reason="no supported package manager detected (rpm, dpkg)"` | The single `integrity.su_binary` check auto-selects a backend in `internal/integrity.Detect()`; Skip when none applies. There are NOT two sibling checks. |
| Non-root user runs the AF_ALG-active-users check | **Skip** with `reason="requires root to enumerate /proc/<pid>/fd/*"` | Documented degradation; check uses native `/proc` parsing, not `lsof` (see §11) |
| Check panics due to a bug | **Error** with stack trace logged at slog ERROR | Bugs surface loudly, never crash the binary |
| Check exceeds `--timeout` | **Error** with `Err: "deadline exceeded"` | Operator can raise `--timeout` |
| Parent ctx cancelled mid-check (SIGINT/SIGTERM) | **Error** with `Err: "context canceled"`; CLI exits 130/143 | Partial Report still written |

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
- Strict semver applied to the JSON wire shape:

  | Change to `report.Report` JSON | Schema bump |
  |---|---|
  | Adding a new optional field (`omitempty`, no consumer impact) | Patch |
  | Adding a new field that consumers SHOULD start emitting/checking but old consumers can ignore | Minor |
  | Adding a new **required** field (consumers must emit/parse it) | **Major** — breaking change |
  | Renaming or removing any field | **Major** |
  | Changing the type of any field (e.g., `int` → `string`) | **Major** |
  | Tightening a value enum (e.g., dropping a `State` constant) | **Major** |
  | Adding a new value to an enum (e.g., adding `StateXxx`) | **Minor** — new consumers must handle it, but old consumers see it as an opaque string |

- Documented in `docs/schema.md`; validated in CI against `schemas/report-1.0.0.json`.
- The schema version is independent of the tool version (§10) — a tool v1.4.2 may still emit schema v1.0.0; bumping the tool to v2.x does NOT automatically bump the schema and vice versa.

### Canonical-JSON form (for `--sign`)

The optional `--sign` flag (§4) writes a SHA-256 digest of the report alongside the report file. To make that digest reproducible across Go versions and minor encoder changes, we serialize the canonical form per [RFC 8785 (JSON Canonicalization Scheme)](https://www.rfc-editor.org/rfc/rfc8785): UTF-8, sorted object keys, no insignificant whitespace, integers without trailing `.0`, escape rules per §3.2 of the RFC. The digest is written as a single line `<sha256-hex>  <filename>` matching `sha256sum`'s output format so operators can verify with stock tools.

## 6. Error Handling & Exit Codes

### Exit code contract (frozen at v1.0.0)

The exit code is computed from `Report.Summary.Required` only. Advisory results never affect the exit code.

```
priority order (first match wins):
  if usage error (bad flag, parse failure)        → 64
  if SIGINT received during run                   → 130
  if SIGTERM received during run                  → 143
  if tool-level error before any check ran        → 3
  if Required.Fail   > 0                          → 2     (definitive mitigation gap)
  if Required.Error  > 0                          → 4     (could not fully validate)
  otherwise                                       → 0
```

| Code | Meaning |
|---|---|
| **0** | All required checks returned `StatePass` (advisory `Fail`, advisory/required `Skip`, advisory `Error` are tolerated) |
| **2** | ≥1 required check returned `StateFail` (host has a definite mitigation gap) |
| **3** | Tool-level error before any check ran (cannot read flags, write output, detect host info, etc.) |
| **4** | ≥1 required check returned `StateError` AND no required check returned `StateFail` (we could not fully validate; treat host posture as **Unknown**) |
| **64** | Usage error (`EX_USAGE` from `sysexits.h`): bad flag, unknown `--format` value, conflicting `--only`/`--skip` |
| **130** | Interrupted by `SIGINT` (POSIX `128 + 2`) |
| **143** | Interrupted by `SIGTERM` (POSIX `128 + 15`) |

**Why exit code 2 wins over 4:** a required `Fail` is a known-bad outcome; a required `Error` is a known-unknown. Definitive bad ranks worse than indeterminate. Operators get one clear signal per host: "vulnerable", "unverifiable", or "good".

**Why advisory `Error` doesn't escalate:** an advisory check that errors (e.g., `lsof` not installed for the AF_ALG-active-users check) is no worse than that check being marked `Skip` upfront. The information asymmetry isn't worth the alert noise. Advisory errors still appear in the report and metrics for forensic value.

**Schema correspondence:** these rules are computable from `Summary.Required.{Pass,Fail,Error}` (the `Bucket` type added in §4) plus a sentinel for "tool error before any check ran". This is why `Bucket` was extended in this revision to include `Error` — without it, the CLI couldn't distinguish exit 2 from exit 4 without re-iterating `Results`.

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
| Sensitive data in output | Hostnames included (necessary). No MAC/machine-id/IP/users unless `--include-host-detail`. `internal/redact.Redact()` strips secret-like substrings from any string emitted into `Evidence` or `Detail`. See "Redaction pattern" below for the exact regex; pattern is a single `const RedactionPattern` in `internal/redact/redact.go`. |

### Redaction pattern

`internal/redact.Redact(s string) string` matches the following Go regex (raw-string literal, so backslashes are literal):

```go
const RedactionPattern = `(?i)(password|passwd|token|secret|bearer|api[_-]?key|aws_(?:access|secret)_key_id?|authorization)\s*[:=]\s*\S+`
```

Replacement: the entire match is replaced with the keyword followed by `=***REDACTED***` — e.g., `aws_secret_access_key=AKIAIOSFODNN7EXAMPLE` becomes `aws_secret_access_key=***REDACTED***`. The keyword is preserved so operators can see *which* secret was found, just not its value.

Test coverage (in `internal/redact/redact_test.go`):

- **Positive matches**: real-looking AWS access keys, JWT-shaped bearer tokens, `password=...` in connection strings, `Authorization: Bearer ...` headers from captured stderr.
- **Negative matches** (must NOT redact): the literal word "password" appearing in a sentence ("Reset your password from the portal"), `secrets.yaml` as a filename, "API key documentation" as a description.

The pattern is intentionally tuned for high precision over high recall — false positives in audit output would be more disruptive than the rare missed redaction. CI runs the test suite against a corpus of 100 samples (50 positive, 50 negative) committed to `internal/redact/testdata/`.

### Out of scope

- Root attacker on the host. Documented in `SECURITY.md` — we are a compliance reporter, not an EDR.
- Kernel-level evasion. Same reasoning.
- Adversarial local users. Tool is meant for root or SSM Agent.

### `internal/exec` — safe subprocess wrapper

**Scope of defense:** `internal/exec` defends against **shell-injection-class** problems only — preventing arbitrary command execution from untrusted argument values. It explicitly does **not** defend against path-traversal, file-overwrite, or resource-exhaustion outside of its own subprocess timeout. Path-traversal protection is the responsibility of the caller layer that knows the path semantics (e.g., the `--conf` flag handler in `cmd/copyfail-validate` runs `filepath.Clean` and an under-`/etc/modprobe.d/` containment check before passing the path anywhere). This separation of concerns is intentional: the exec wrapper does not have enough context to know whether a slash-containing argument is a legitimate path (good) or a traversal attempt (bad).

```go
package exec // internal

// Untrusted is a string from a user-controlled source (flag, env var,
// subprocess output that will be re-fed to another subprocess). It MUST
// pass UntrustedArgRE before being placed into a Cmd.Args slot.
type Untrusted string

// Trusted is a string the caller asserts is safe — typically a constant
// or a value validated by a domain-specific validator (e.g., a path
// already cleaned and contained by the --conf flag handler). The exec
// wrapper passes Trusted values through without character validation.
type Trusted string

// Arg is the argument-slot type accepted by Cmd.Args. Concrete types are
// Untrusted and Trusted; new types MUST NOT be added without security review.
type Arg interface{ argSentinel() }

func (Untrusted) argSentinel() {}
func (Trusted) argSentinel()   {}

type Cmd struct {
    Name    string        // logical name (not a path); resolved via allowedCommands
    Args    []Arg         // each Untrusted Arg must match UntrustedArgRE
    Timeout time.Duration // 0 = 30s default
    Env     []string      // 0-len = minimal: PATH, LANG=C
}

type Result struct {
    Stdout   []byte // bounded to MaxOutput (1 MiB); excess dropped, marker set in Truncated
    Stderr   []byte
    Truncated bool
    ExitCode int
    Path     string // resolved absolute path of the executable that ran
    Duration time.Duration
}

// allowedCommands maps logical name → preferred absolute path.
// Lookup falls back to exec.LookPath only if the absolute path is missing.
var allowedCommands = map[string]string{
    "modprobe": "/sbin/modprobe",
    "lsmod":    "/sbin/lsmod",
    "uname":    "/bin/uname",
    "rpm":      "/usr/bin/rpm",
    "dpkg":     "/usr/bin/dpkg",
    "dpkg-query": "/usr/bin/dpkg-query",
    "debsums":  "/usr/bin/debsums",
    "sha256sum": "/usr/bin/sha256sum",
}

// UntrustedArgRE matches the conservative set of characters allowed in an
// Untrusted argument: alphanumerics, dot, underscore, hyphen, forward
// slash, plus, colon, equals, comma, at-sign. NOTE: this regex deliberately
// permits forward slash (because legitimate values include package names
// and absolute paths) and does NOT block ".." segments — that is the
// caller's responsibility per the "Scope of defense" note above. Leading
// "-" is ALSO blocked by a separate check (prevents flag-injection like
// `--config=/etc/passwd`).
var UntrustedArgRE = regexp.MustCompile(`^[A-Za-z0-9._\-/+:=,@]+$`)

func (c Cmd) Run(ctx context.Context) (Result, error)
```

Properties:
- **No shell.** Never call `sh`, `bash`, or `system()`. Period.
- **Allowlisted commands.** Non-allowlisted `Name` → `ErrCommandDenied`. Note that `lsof` was removed from the allowlist in this revision: the AF_ALG-active-users check now reads `/proc/<pid>/fd/*` directly (see §11), eliminating the only need for `lsof`.
- **Two-tier argument typing.** `Untrusted` args must pass `UntrustedArgRE` AND must not start with `-` (flag-injection guard). `Trusted` args bypass — typically used for fixed flags like `Trusted("-V")` or paths already validated by the caller. The compiler enforces the distinction at every call site via the `Arg` interface.
- **Minimal environment.** `LANG=C` for parser determinism. `PATH` for `LookPath`. Nothing else by default; callers may add specific vars but never the entire host env.

**Caller responsibilities** (NOT enforced by `internal/exec`):
- Path-traversal protection on file paths (use `filepath.Clean` + containment check before passing as `Trusted`).
- Numeric range checks on values that will be parsed as ints by a subprocess.
- Domain-specific validation (e.g., RPM package name format, kernel module name format).

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

### Semver discipline (tool version)

The tool version follows strict semver. The `Report.SchemaVersion` is independent (see §5) — a tool minor bump may or may not coincide with a schema bump.

| Change | Tool bump |
|---|---|
| New check in `preset/copyfail` (consumers' fleets simply check more things; no API change) | Patch |
| New public function/method/type | Minor |
| Adding a new optional field to `report.Report` (no required change for consumers) | Minor (schema patch — see §5) |
| Adding a new value to a public enum (e.g., adding `report.StateXxx`) | Minor (schema minor) |
| Adding a new required field to `report.Report` | **Major** (schema major) |
| Removing or renaming any exported symbol | **Major** |
| Changing exit code semantics (codes 0/2/3/4/64/130/143 are frozen at v1.0.0) | **Major** |
| Bumping `Report.SchemaVersion` major | **Major** |
| Removing or renaming any check ID from a preset (existing IDs are frozen at v1.0.0) | **Major** |

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
| `modprobe.dependency_chain` | No `install algif_aead /bin/true` or trivial-bypass directive in any `/etc/modprobe.d/*.conf` | required | always | Defense-in-depth — catches an attacker or misconfigured tool that overrode the blocklist with a permissive directive in a file that sorts later alphabetically |
| `module.not_loaded` | Target module absent from `/proc/modules` | required | always | Parses `/proc/modules` directly (no shell) |
| `afalg.no_active_users` | No process has an AF_ALG-family kernel module mapped | advisory | requires root to enumerate `/proc/<pid>/maps` for processes other than self | See parser contract below |
| `integrity.su_binary` | `/usr/bin/su` matches package manager records | advisory | `rpm` OR `dpkg` present (auto-selected via `internal/integrity.Detect()`); Skip when neither is present | Single check, single result row in the report; backend identity recorded in `Evidence["backend"]` |
| `hostinfo.os_release` | `/etc/os-release` parseable | advisory | always | Populates `host.os_release` / `host.os_version_id` |

#### `afalg.no_active_users` — parser contract (no shell, no `lsof`)

The current `copyfail_validator.go` uses `sh -c "lsof | grep -q AF_ALG; echo $?"` — a textbook injection vector AND an unnecessary external dependency. The replacement avoids both, implemented in `internal/procscan`:

**Preconditions:**

- Process EUID is 0 (verified via `os.Geteuid()`). If not, return `StateSkip` with `skipped_reason="requires root to enumerate /proc/<pid>/fd/*"`.
- `/proc` is mounted (verified via `os.Stat("/proc/self")`). If not, return `StateError` with `Err="/proc not mounted"`.

**Detection algorithm:**

1. List PIDs: `os.ReadDir("/proc")`, filter to entries whose name parses as a positive integer.
2. For each PID, try to scan its memory map: `os.ReadFile("/proc/<pid>/maps")`.
   - On `EACCES` → record in `Evidence["unreadable_pids"]`, continue.
   - On `ENOENT` → process exited mid-scan, ignore silently.
3. Within the maps file, look for any line whose pathname column contains `algif_aead` (kernel module path) or any of the AF_ALG-family module names (`af_alg`, `algif_skcipher`, `algif_hash`, `algif_rng` — full list in `internal/procscan/afalg.go`).
4. Read `/proc/<pid>/comm` for matched PIDs to populate the human-readable process name in Evidence.

**Why we don't enumerate AF_ALG sockets directly:** AF_ALG sockets are NOT visible in `/proc/net/tcp`, `/proc/net/unix`, or any other `/proc/net/*` file readable without `CAP_NET_ADMIN`. The kernel's algif accounting is reachable only via netlink queries that require elevated capabilities we deliberately do not request. The maps-based heuristic above is what's actually achievable from userspace as root, and it catches every realistic legitimate consumer (encrypted-filesystem daemons, hardware-offload crypto users) plus any malicious user that has the module mapped.

**Postconditions / state mapping:**

| Result | State |
|---|---|
| `candidate_processes` is empty | `StatePass` |
| `candidate_processes` is non-empty | `StateFail` (advisory severity — flagged for investigation, not necessarily malicious) |
| `os.Geteuid() != 0` | `StateSkip` |
| `/proc` not readable | `StateError` |

**Evidence shape:**

```jsonc
"evidence": {
  "method": "proc_maps_scan",
  "scanned_pids": 412,
  "unreadable_pids": 3,
  "candidate_processes": [
    {"pid": 1817, "comm": "encfs", "match_reason": "algif_aead in /proc/1817/maps"}
  ],
  "skipped_reason": ""
}
```

The current code's checks 1–6 are preserved (with `module.not_loaded` migrated off `sh -c` and `afalg.no_active_users` migrated off the `lsof | grep` shell pipe). Checks added relative to today's code: `modprobe.conf_present` is split out from `modprobe.conf_correct` for clearer reporting; `modprobe.dependency_chain` is new (defense-in-depth against blocklist override); `kernel.version` and `hostinfo.os_release` become explicit checks rather than implicit fields.

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
