# copyfail-validation

[![Go Reference](https://pkg.go.dev/badge/github.com/polyglotdev/copyfail-validation.svg)](https://pkg.go.dev/github.com/polyglotdev/copyfail-validation)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> A defensive validator for Linux hosts against the AF_ALG-family
> kernel-crypto vulnerabilities, starting with **CVE-2026-31431**
> ("copyfail").

## What it is

`copyfail-validation` is a single-binary Go tool (and reusable Go library)
that checks whether a Linux host has applied the defensive mitigations for
the copyfail kernel-crypto exploit. It is **read-only** — it never modifies
host state, never attempts exploitation, never executes shell pipelines,
and never reaches the network. Subprocess invocations go through an
allowlisted, argument-validated wrapper with hard timeouts and bounded
output capture. The tool is designed to run as `root` from a cron job, an
SSM Run Command, a Lambda, or interactively at the shell.

## Quick start

Install and run the CLI:

```bash
go install github.com/polyglotdev/copyfail-validation/cmd/copyfail-validate@latest
sudo copyfail-validate
```

Sample human-format output (one required check failed; required `Skip`
and an advisory check are tolerated):

```
copyfail-validation v0.1.0  •  host=ip-10-0-12-34  •  duration=42ms

  PASS  modprobe.conf_present       blocklist file present at /etc/modprobe.d/disable-algif-aead.conf (84 bytes)
  PASS  modprobe.conf_correct       both install + blacklist directives present
  FAIL  modprobe.dry_run            modprobe -n -v algif_aead resolved to insmod /lib/modules/.../algif_aead.ko (expected /bin/false)
  PASS  modprobe.dependency_chain   no override directives found in /etc/modprobe.d (12 files scanned)
  PASS  module.not_loaded           algif_aead absent from /proc/modules

Required:  4 pass, 1 fail, 0 skip, 0 error
Advisory:  0 pass, 0 fail, 0 skip, 0 error
```

For machine-readable output use `--format=json` (default for SSM / Lambda
postprocessing) or `--format=sarif` for a code-scanning upload, or
`--format=prometheus` for a textfile-collector drop.

## Architecture

```
                ┌───────────────────────────────┐
                │  cmd/copyfail-validate (CLI)  │
                └───────────────┬───────────────┘
                                │
                                ▼
                ┌───────────────────────────────┐
                │  preset/copyfail              │   public; check.Check impls
                │  (5 required + 4 advisory)    │
                └───────────────┬───────────────┘
                                │
                ┌───────────────┴───────────────┐
                ▼                               ▼
   ┌────────────────────────┐     ┌────────────────────────┐
   │  check                 │     │  internal/...          │
   │  (Check, Runner)       │     │  (kernelmod, exec,     │
   │                        │     │   procscan, integrity, │
   │                        │     │   hostinfo, render)    │
   └────────────┬───────────┘     └────────────┬───────────┘
                │                              │
                └──────────────┬───────────────┘
                               ▼
                ┌──────────────────────────────┐
                │  report                       │  value types only
                │  (State, Severity, Result,    │  (no deps in module)
                │   Report, Format, Summary)    │
                └──────────────────────────────┘
```

The layering rule: **`report` is the leaf** — it imports nothing else in
this module, so library consumers can depend on `report` types alone
without pulling in subprocess or kernel-introspection code. Public
sub-packages (`check`, `preset/copyfail`) import `report`. Everything
under `internal/` is implementation detail and changes without notice.

## Output formats

- **`human`** (default for TTY) — colorised summary with one line per
  check, suitable for interactive use.
- **`json`** — canonical JSON document matching the schema in
  `Report.SchemaVersion`. Stable across patch releases of the same
  minor; consumed by SSM / Lambda postprocessing.
- **`sarif`** — SARIF 2.1.0 log with one rule per check, ready to upload
  to GitHub code-scanning or any SARIF-aware viewer.
- **`prometheus`** — line-oriented `copyfail_check_state{...}` gauges,
  ready to drop into the node-exporter textfile collector.

## Exit codes

The exit code is computed from the **required** check bucket only;
advisory results never affect it. (Frozen at v1.0.0; see spec §6.)

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| 0    | All required checks passed                               |
| 2    | ≥1 required check returned `Fail` (definite mitigation gap) |
| 3    | Tool-level error before any check ran                    |
| 4    | ≥1 required check returned `Error` (cannot fully validate) |
| 64   | Usage error (`EX_USAGE`): bad flag, conflicting `--only`/`--skip` |
| 130  | Interrupted by `SIGINT`                                  |
| 143  | Interrupted by `SIGTERM`                                 |

A required `Fail` outranks a required `Error` (definitive bad outranks
indeterminate). One clear signal per host: vulnerable, unverifiable, or
good.

## Library usage

The same checks the CLI runs are available as a Go library:

```go
package main

import (
    "context"
    "os"

    "github.com/polyglotdev/copyfail-validation/check"
    _ "github.com/polyglotdev/copyfail-validation/internal/render" // registers JSON/SARIF/Prometheus/human renderers
    "github.com/polyglotdev/copyfail-validation/preset/copyfail"
    "github.com/polyglotdev/copyfail-validation/report"
)

func main() {
    runner := &check.Runner{}                             // zero value is valid
    rep := runner.Run(context.Background(), copyfail.All())
    if _, err := rep.WriteTo(os.Stdout, report.FormatJSON); err != nil {
        os.Exit(3)
    }
    if rep.Summary.Required.Fail > 0 {
        os.Exit(2)
    }
}
```

The `report` package is deliberately dependency-free within this module —
embedding it in your own pipeline does not pull in subprocess or kernel
introspection code. See the package godoc on
[pkg.go.dev](https://pkg.go.dev/github.com/polyglotdev/copyfail-validation)
for the full API.

## Status & versioning

**Pre-v0.1.0.** The library API may shift before v0.1.0 ships; the JSON
output schema is versioned independently (`Report.SchemaVersion`,
currently `v1.0.0` — see [CHANGELOG.md](CHANGELOG.md)). Once v1.0.0
ships, both surfaces follow strict semver per spec §10's bump table.

Tracked module path: `github.com/polyglotdev/copyfail-validation`.
CLI binary: `copyfail-validate`.

## Documentation

- [`SECURITY.md`](SECURITY.md) — vulnerability reporting and disclosure policy.
- [`CHANGELOG.md`](CHANGELOG.md) — release notes (Keep-a-Changelog format).
- [`docs/checks.md`](docs/checks.md) — full check catalog with severity,
  applicability, state semantics, and Evidence shapes for every check ID.
- [`docs/superpowers/specs/2026-05-04-copyfail-validation-design.md`](docs/superpowers/specs/2026-05-04-copyfail-validation-design.md)
  — the design spec.
- [`docs/superpowers/plans/2026-05-04-copyfail-validation-v0.1.md`](docs/superpowers/plans/2026-05-04-copyfail-validation-v0.1.md)
  — the v0.1.0 implementation plan.

## License

Apache-2.0. See [LICENSE](LICENSE).
