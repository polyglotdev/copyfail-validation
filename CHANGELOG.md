# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The JSON output schema (`Report.SchemaVersion`) is versioned **independently**
of the tool. The schema-versioning contract is documented in `docs/schema.md`
(landing in Phase 7 of the v0.1.0 implementation plan).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.1.0] - 2026-05-04

### Added

- Public `report` package: `State`, `Severity`, `Result`, `Report`, `Format`,
  `Summary`, `Bucket`, `ToolInfo`, `HostInfo` value types; `WriteTo` dispatch
  with renderer registry; `ParseFormat` with sentinel error; SARIF state
  mapping; `SnapshotRenderers` / `RestoreRenderers` for test isolation.
- Public `check` package: `Check` interface and bounded-parallel `Runner` with
  panic recovery and deterministic ordering.
- Public `preset/copyfail` package: 5 required checks for CVE-2026-31431
  (`modprobe.conf_present`, `modprobe.conf_correct`, `modprobe.dry_run`,
  `modprobe.dependency_chain`, `module.not_loaded`) plus `CVE` const,
  `Options`, and `All` / `AllWithOptions` bundlers.
- CLI `copyfail-validate` (`cmd/copyfail-validate`) with main, flags, and
  exit-code computation; integration tests covering every exit-code path.
- 4 output formats wired through `internal/render`: human (default on TTY),
  json (default off-TTY), sarif (security tooling), prometheus (textfile
  collector).
- Internal packages: `exec` (safe subprocess wrapper with Trusted/Untrusted
  Arg interface, allowlist + ResolveCommand, three Runner implementations),
  `kernelmod` (`/proc/modules` parser, `/etc/modprobe.d` later-wins parser,
  safe `modprobe -nv` wrapper), `integrity` (pluggable `PkgMgr` backend with
  rpm and dpkg), `procscan` (AF_ALG family detection via `/proc/<pid>/maps`),
  `hostinfo` (Gather + os-release parser), `logging` (slog factory with
  verbosity levels and run_id), `redact` (`Redact()` with pattern + corpus),
  `canonjson` (RFC 8785 JCS canonicalizer subset), `render` (the four
  renderers above), `buildinfo` (ldflags-injected Version/Commit/BuildDate).
- `LICENSE` (Apache-2.0), `README.md` (architecture, quickstart, library
  usage), `SECURITY.md` (90-day coordinated-disclosure policy), `docs/checks.md`
  (per-check catalog: 5 implemented + 4 planned), `doc.go` (module-level
  pkg.go.dev landing page).
- Build / release tooling: `Makefile` (lint, test, cover, vuln, fuzz, build,
  clean), `.golangci.yml` with depguard import-graph rules, `.goreleaser.yaml`
  for v0.1.0, GitHub Actions workflows for tests (race + lint + vuln + SPDX)
  and tagged release.
- SPDX license headers on all Go files.

### Security

- All subprocess invocations go through `internal/exec` with Trusted /
  Untrusted Arg typing — no shell, no string-formatted command lines, no
  `lsof`. The exec wrapper preserves the `ErrOutputTruncated` sentinel even
  when the subprocess exits non-zero.
- `internal/redact` correctly handles `AWS_SECRET_ACCESS_KEY` (a real spec
  bug caught and fixed in Phase 1B) and `Authorization: Bearer …` JWTs with
  a line-bounded match so adjacent fields are not over-redacted.

### Fixed

- Import-cycle between `report` and the renderer registry resolved via
  `WriteTo` dispatch + `SnapshotRenderers` / `RestoreRenderers`.
- depguard glob in `.golangci.yml` corrected to actually match files in
  `report/` and `check/`.
- `internal/exec` preserves `ErrOutputTruncated` when subprocess also exits
  non-zero (was being shadowed by the exit-code error).

### Deferred to v0.1.x

The following items were scoped into the v0.1 plan but are NOT in `v0.1.0`.
They are planned for the v0.1.x point-release stream:

- 4 advisory checks (`kernel.version`, `hostinfo.os_release`,
  `afalg.no_active_users`, `integrity.su_binary`).
- Integration smoke test.
- SSM and Prometheus runbooks.
- `examples/basic/` runnable demo.
- Distroless Dockerfile.
- cosign signing, SLSA L3 provenance, SBOM generation.
- OpenSSF Scorecard, CodeQL, Dependabot.
- End-to-end Dockerfiles for AL2023, Ubuntu 22.04, Rocky 9 drift scenarios
  (Task 8.1).

[Unreleased]: https://github.com/polyglotdev/copyfail-validation/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/polyglotdev/copyfail-validation/releases/tag/v0.1.0
