# copyfail-validation v0.1 Implementation Plan

> **For agentic workers:** REQUIRED: Use `superpowers:subagent-driven-development` (if subagents available) or `superpowers:executing-plans` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `github.com/polyglotdev/copyfail-validation` v0.1.0 to pkg.go.dev with a publishable Go library, a `copyfail-validate` CLI installable via `go install`, and signed cross-arch release artifacts on GitHub Releases.

**Architecture:** Standard Go layout with three public packages (`report` as the dependency-graph leaf, `check` for behavior, `preset/copyfail` as the day-one validator bundle), `internal/*` for shell-injection-safe subprocess wrappers, kernel-module / `/proc` parsers, package-manager backends, output renderers, and supporting helpers. CLI is a ~30 LOC frontend over the library. Multi-format output (human / JSON / SARIF / Prometheus textfile) renders from one canonical `Report`.

**Tech Stack:** Go 1.26.2 (stdlib-only at runtime; `github.com/google/go-cmp` is the sole test-only dependency), `golangci-lint` with `depguard` for the import-graph rule, GoReleaser for cross-arch builds + nfpm packages + container image, GitHub Actions for CI / release / Scorecard / CodeQL, cosign keyless + SLSA L3 generator + syft for supply-chain artifacts.

**Source spec:** [docs/superpowers/specs/2026-05-04-copyfail-validation-design.md](../specs/2026-05-04-copyfail-validation-design.md)

---

## Plan Overview

The plan is divided into **9 phases** across **5 chunks**:

| Chunk | Phases | Focus | Parallelizable? |
|---|---|---|---|
| 1 | 0, 1 | Bootstrap (LICENSE, lint, CI scaffolding) + leaf data layer (`report`, `internal/{redact,buildinfo,canonjson}`) | Phase 1 packages parallel after Phase 0 |
| 2 | 2 | Internal helpers (`internal/{exec,hostinfo,logging,kernelmod,integrity,procscan}`) | `exec` first; rest parallel after |
| 3 | 3, 4 | Behavior (`check`) + renderers (`internal/render/*`) | Renderers parallel; `check` blocks `preset` |
| 4 | 5, 6 | `preset/copyfail` checks + `cmd/copyfail-validate` CLI | Sequential within phase; phases sequential |
| 5 | 7, 8 | Distribution (goreleaser, GH Actions, docs, schemas) + e2e + v0.1.0 release | Distribution items mostly parallel; release tag is the terminal step |

**Critical path to v0.1.0** (the smallest set of steps that must complete in order):

```
Phase 0 → Phase 1 (report) → Phase 2 (exec) → Phase 3 (check) → Phase 5 (preset)
       → Phase 6 (CLI) → Phase 7 (LICENSE headers + README + CHANGELOG + minimal goreleaser)
       → Phase 8 (tag v0.1.0)
```

Everything else is "nice to have for v0.1 but can ship in v0.1.x patches" (Prometheus rendering, SARIF rendering, e2e Dockerfiles, OTel hook). The CRITICAL PATH steps are flagged with **🚀 RELEASE BLOCKER** at task level.

**Skill cross-references** (load these when working a task that touches the relevant area):

| Area | Skill |
|---|---|
| Any test work | `cc-skills-golang:golang-testing` |
| `internal/exec`, `internal/integrity`, secret redaction | `cc-skills-golang:golang-security` |
| Any `os.ReadFile` / `os.OpenFile` of host paths | `cc-skills-golang:golang-safety` |
| Slog setup, Prometheus exposition, OTel hook | `cc-skills-golang:golang-observability` |
| `internal/exec` design, `Cmd`/`Result` types | `cc-skills-golang:golang-design-patterns` |
| Concurrency in `check.Runner` | `cc-skills-golang:golang-concurrency` |
| Error sentinels, `%w`, `errors.Is/As` | `cc-skills-golang:golang-error-handling` |
| Project layout decisions (already locked by spec) | `cc-skills-golang:golang-project-layout` |
| godoc style, README, CHANGELOG | `cc-skills-golang:golang-documentation` |
| `.golangci.yml` configuration | `cc-skills-golang:golang-linter` |
| Benchmarks for parsers | `cc-skills-golang:golang-benchmark` |
| GoReleaser, Dockerfile, GitHub Actions | `cc-skills-golang:golang-continuous-integration` |
| Sentinel + wrapped errors throughout | `cc-skills-golang:golang-error-handling` |

**Conventions used in every task:**

- **TDD:** every task starts with a failing test, then minimal implementation, then green test, then commit.
- **Commits:** Conventional Commits prefix (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:`, `ci:`, `chore:`). NO Claude / AI attribution lines (project preference).
- **Test parallelism:** every `*_test.go` calls `t.Parallel()` at the top of every test and subtest.
- **Sentinel errors:** package-level `var Err... = errors.New(...)` for typed error matching; wrap with `fmt.Errorf("pkg: doing X: %w", err)` at every layer crossing.
- **godoc:** every exported symbol gets a complete-sentence comment beginning with the symbol name, present from the moment the symbol is added.
- **License header:** every `.go` file (including tests) gets the SPDX header per `Phase 7` step (added in bulk near the end; CI fails the build if any file is missing it post-Phase-7).

---

## File Structure (locked by Phase 0)

```
copyfail-validation/
├── LICENSE                                            # Phase 0
├── README.md                                          # Phase 0 (skeleton) + Phase 7 (full)
├── CHANGELOG.md                                       # Phase 0 (skeleton) + every commit thereafter
├── SECURITY.md                                        # Phase 7
├── CONTRIBUTING.md                                    # Phase 7
├── CODE_OF_CONDUCT.md                                 # Phase 7
├── RELEASING.md                                       # Phase 7
├── .gitignore                                         # already done
├── .golangci.yml                                      # Phase 0
├── .goreleaser.yaml                                   # Phase 7
├── Dockerfile.release                                 # Phase 7
├── Makefile                                           # Phase 0 (basic) + Phase 8 (e2e targets)
├── go.mod                                             # already exists; Phase 0 verifies + adds go-cmp
├── go.sum                                             # generated
├── doc.go                                             # Phase 7 (module-level godoc)
│
├── report/
│   ├── doc.go                                         # Phase 1 task 1.1
│   ├── state.go                                       # Phase 1 task 1.2
│   ├── state_test.go                                  # Phase 1 task 1.2
│   ├── severity.go                                    # Phase 1 task 1.3
│   ├── severity_test.go                               # Phase 1 task 1.3
│   ├── format.go                                      # Phase 1 task 1.4
│   ├── format_test.go                                 # Phase 1 task 1.4
│   ├── result.go                                      # Phase 1 task 1.5
│   ├── result_test.go                                 # Phase 1 task 1.5
│   ├── report.go                                      # Phase 1 task 1.6
│   ├── report_test.go                                 # Phase 1 task 1.6
│   ├── writeto.go                                     # Phase 1 task 1.7 (stub) → Phase 4 (real)
│   ├── writeto_test.go                                # Phase 1 task 1.7
│   └── example_test.go                                # Phase 7
│
├── check/
│   ├── doc.go                                         # Phase 3 task 3.1
│   ├── check.go                                       # Phase 3 task 3.2 (Check interface + Severity getter)
│   ├── check_test.go                                  # Phase 3 task 3.2
│   ├── runner.go                                      # Phase 3 task 3.3
│   ├── runner_test.go                                 # Phase 3 task 3.3
│   ├── runner_concurrency_test.go                     # Phase 3 task 3.4
│   └── example_test.go                                # Phase 7
│
├── preset/
│   └── copyfail/
│       ├── doc.go                                     # Phase 5 task 5.1
│       ├── copyfail.go                                # Phase 5 task 5.2 (CVE const + All())
│       ├── copyfail_test.go                           # Phase 5 task 5.2
│       ├── kernel_version.go                          # Phase 5 task 5.3
│       ├── kernel_version_test.go                     # Phase 5 task 5.3
│       ├── modprobe_conf_present.go                   # Phase 5 task 5.4
│       ├── modprobe_conf_present_test.go              # Phase 5 task 5.4
│       ├── modprobe_conf_correct.go                   # Phase 5 task 5.5
│       ├── modprobe_conf_correct_test.go              # Phase 5 task 5.5
│       ├── modprobe_dry_run.go                        # Phase 5 task 5.6
│       ├── modprobe_dry_run_test.go                   # Phase 5 task 5.6
│       ├── modprobe_dependency_chain.go               # Phase 5 task 5.7
│       ├── modprobe_dependency_chain_test.go          # Phase 5 task 5.7
│       ├── module_not_loaded.go                       # Phase 5 task 5.8
│       ├── module_not_loaded_test.go                  # Phase 5 task 5.8
│       ├── afalg_no_active_users.go                   # Phase 5 task 5.9
│       ├── afalg_no_active_users_test.go              # Phase 5 task 5.9
│       ├── integrity_su_binary.go                     # Phase 5 task 5.10
│       ├── integrity_su_binary_test.go                # Phase 5 task 5.10
│       ├── hostinfo_os_release.go                     # Phase 5 task 5.11
│       ├── hostinfo_os_release_test.go                # Phase 5 task 5.11
│       └── example_test.go                            # Phase 7
│
├── internal/
│   ├── exec/                                          # Phase 2 (FIRST — blocks kernelmod, integrity)
│   │   ├── arg.go                                     # Trusted/Untrusted/Arg interface
│   │   ├── arg_test.go
│   │   ├── allowlist.go                               # allowedCommands map
│   │   ├── allowlist_test.go
│   │   ├── cmd.go                                     # Cmd struct + Run method
│   │   ├── cmd_test.go
│   │   ├── runner.go                                  # Runner interface + osRunner + FakeRunner
│   │   ├── runner_test.go
│   │   ├── helper_test.go                             # TestHelperProcess pattern
│   │   └── errors.go                                  # ErrCommandDenied, ErrCommandNotFound, ErrTimeout
│   ├── kernelmod/
│   │   ├── procmodules.go                             # /proc/modules parser
│   │   ├── procmodules_test.go
│   │   ├── procmodules_fuzz_test.go
│   │   ├── modprobe.go                                # modprobe -nv parser + invocation
│   │   ├── modprobe_test.go
│   │   ├── conf.go                                    # /etc/modprobe.d/*.conf parser
│   │   ├── conf_test.go
│   │   └── conf_fuzz_test.go
│   ├── integrity/
│   │   ├── pkgmgr.go                                  # PkgMgr interface + Detect()
│   │   ├── pkgmgr_test.go
│   │   ├── rpm.go
│   │   ├── rpm_test.go
│   │   ├── dpkg.go
│   │   └── dpkg_test.go
│   ├── procscan/
│   │   ├── afalg.go                                   # AF_ALG family detection via /proc/<pid>/maps
│   │   ├── afalg_test.go
│   │   └── modules.go                                 # known AF_ALG-family module names
│   ├── render/
│   │   ├── render.go                                  # dispatch (called from report.WriteTo)
│   │   ├── render_test.go
│   │   ├── human.go
│   │   ├── human_test.go
│   │   ├── json.go
│   │   ├── json_test.go
│   │   ├── sarif.go
│   │   ├── sarif_test.go
│   │   ├── prom.go                                    # Prometheus textfile + atomic write
│   │   ├── prom_test.go
│   │   └── testdata/golden/*.txt                      # human-format goldens
│   ├── hostinfo/
│   │   ├── hostinfo.go                                # /etc/os-release + uname + hostname
│   │   ├── hostinfo_test.go
│   │   └── osrelease_fuzz_test.go
│   ├── redact/
│   │   ├── redact.go                                  # RedactionPattern const + Redact()
│   │   ├── redact_test.go
│   │   └── testdata/
│   │       ├── positive/                              # 50 samples; each redacts to expected output
│   │       └── negative/                              # 50 samples; each must NOT be redacted
│   ├── buildinfo/
│   │   ├── buildinfo.go                               # Version, Commit, BuildDate vars set via -ldflags
│   │   └── buildinfo_test.go
│   ├── canonjson/
│   │   ├── canonjson.go                               # RFC 8785 (JCS) canonicalizer
│   │   ├── canonjson_test.go
│   │   └── testdata/                                  # JCS test vectors from the RFC
│   └── logging/
│       ├── logging.go                                 # slog construction
│       └── logging_test.go
│
├── cmd/
│   └── copyfail-validate/
│       ├── main.go                                    # Phase 6 task 6.1 (entry point)
│       ├── flags.go                                   # Phase 6 task 6.2
│       ├── flags_test.go
│       ├── exit.go                                    # Phase 6 task 6.3
│       ├── exit_test.go
│       └── main_test.go                               # Phase 6 task 6.4 (CLI integration tests)
│
├── examples/
│   └── basic/
│       └── main.go                                    # Phase 7
│
├── schemas/
│   └── report-1.0.0.json                              # Phase 7
│
├── docs/
│   ├── checks.md                                      # Phase 7 (catalog)
│   ├── schema.md                                      # Phase 7
│   ├── runbook-ssm.md                                 # Phase 7
│   ├── runbook-prometheus.md                          # Phase 7
│   ├── dependencies.md                                # Phase 7
│   ├── superpowers/specs/...                          # already exists
│   └── superpowers/plans/...                          # this file
│
├── e2e/
│   ├── al2023/Dockerfile                              # Phase 8
│   ├── ubuntu2204/Dockerfile                          # Phase 8
│   ├── rocky9-drift/Dockerfile                        # Phase 8
│   └── run.sh                                         # Phase 8
│
└── .github/
    ├── workflows/
    │   ├── test.yml                                   # Phase 7
    │   ├── release.yml                                # Phase 7
    │   ├── scorecard.yml                              # Phase 7
    │   └── codeql.yml                                 # Phase 7
    ├── dependabot.yml                                 # Phase 7
    └── ISSUE_TEMPLATE/                                # Phase 7
```

**File-deletion plan:** `copyfail_validator.go` at the repo root is the legacy prototype. It is never edited during this plan. It is **deleted in Phase 5 task 5.12** once all 9 checks have feature parity in `preset/copyfail` and pass their tests.

---

## Chunk 1: Bootstrap + Leaf Data Layer (Phases 0–1)

### Phase 0 — Bootstrap

Goal: get the repo into a state where every subsequent commit is auto-linted and the dependency-graph rule is enforced. After Phase 0, no Go code in this module can violate the package layering rule without CI failing.

#### Task 0.1: Add Apache-2.0 LICENSE 🚀 RELEASE BLOCKER

**Files:**
- Create: `LICENSE`

- [ ] **Step 1: Download the canonical Apache-2.0 text**

Run: `curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o /Users/domhallan/projects/personal/copyfail-validation/LICENSE`
Expected: file is exactly 11,357 bytes (Apache's canonical size). Verify with `wc -c /Users/domhallan/projects/personal/copyfail-validation/LICENSE`.

- [ ] **Step 2: Verify content begins correctly**

Run: `head -2 /Users/domhallan/projects/personal/copyfail-validation/LICENSE`
Expected first two lines:
```
                                 Apache License
                           Version 2.0, January 2004
```

- [ ] **Step 3: Commit**

```bash
git add LICENSE
git commit -m "build: add Apache-2.0 LICENSE

pkg.go.dev surfaces a license badge from the canonical /LICENSE file
at module root; this is the file that satisfies that scan."
```

#### Task 0.2: Verify and pin Go module declaration 🚀 RELEASE BLOCKER

**Files:**
- Verify: `go.mod`

- [ ] **Step 1: Read current go.mod**

Run: `cat /Users/domhallan/projects/personal/copyfail-validation/go.mod`
Expected:
```
module github.com/polyglotdev/copyfail-validation

go 1.26.2
```

- [ ] **Step 2: Confirm Go toolchain matches**

Run: `go version`
Expected: `go version go1.26.2 darwin/...` (or newer minor on the same major).

- [ ] **Step 3: Add go-cmp as the only test dependency**

Run: `go get github.com/google/go-cmp@latest`
Expected: `go.mod` gains a `require github.com/google/go-cmp v0.x.y` line; `go.sum` is created.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add github.com/google/go-cmp test dependency

This is the only third-party dependency the module pulls in (test-only).
Used for cmp.Diff in table-driven tests where struct comparison would
otherwise produce unreadable failure messages."
```

#### Task 0.3: Bootstrap golangci-lint config with depguard 🚀 RELEASE BLOCKER

**Files:**
- Create: `.golangci.yml`

- [ ] **Step 1: Write `.golangci.yml`**

Create `/Users/domhallan/projects/personal/copyfail-validation/.golangci.yml`:

```yaml
version: "2"

run:
  timeout: 5m
  tests: true
  modules-download-mode: readonly

linters:
  default: none
  enable:
    - bodyclose
    - depguard
    - errcheck
    - gocritic
    - gosec
    - govet
    - ineffassign
    - misspell
    - revive
    - staticcheck
    - unused
    - unparam

  settings:
    depguard:
      rules:
        report-is-leaf:
          # report/ MUST NOT import anything from this module.
          # See: docs/superpowers/specs/2026-05-04-copyfail-validation-design.md §3 (Design Principles, rule 3).
          files:
            - "**/report/**/*.go"
            - "!**/report/**/*_test.go"   # tests may import internal/render etc. via the public API
          deny:
            - pkg: github.com/polyglotdev/copyfail-validation/check
              desc: "report is the leaf of the dependency graph; check imports report, never the reverse"
            - pkg: github.com/polyglotdev/copyfail-validation/preset
              desc: "report is the leaf of the dependency graph; preset imports report, never the reverse"
            - pkg: github.com/polyglotdev/copyfail-validation/internal
              desc: "report must not import any internal/* package"
            - pkg: github.com/polyglotdev/copyfail-validation/cmd
              desc: "report must not import the CLI"
        check-imports-only-report:
          files:
            - "**/check/**/*.go"
            - "!**/check/**/*_test.go"
          deny:
            - pkg: github.com/polyglotdev/copyfail-validation/preset
              desc: "check must not depend on any concrete preset; presets depend on check"
            - pkg: github.com/polyglotdev/copyfail-validation/cmd
              desc: "check must not depend on the CLI"
    gosec:
      severity: medium
      confidence: medium
      excludes:
        - G204  # subprocess args from variable; mitigated structurally by internal/exec.Trusted/Untrusted
    revive:
      rules:
        - name: exported              # godoc on every exported symbol
        - name: package-comments      # doc.go in every public package
        - name: var-naming
        - name: error-return
        - name: error-naming
        - name: error-strings
        - name: receiver-naming
    govet:
      enable-all: true
    misspell:
      locale: US
    unparam:
      check-exported: true

issues:
  max-issues-per-linter: 0
  max-same-issues: 0

formatters:
  enable:
    - gofmt
    - goimports
  settings:
    goimports:
      local-prefixes:
        - github.com/polyglotdev/copyfail-validation
```

- [ ] **Step 2: Install golangci-lint locally**

Run: `which golangci-lint || brew install golangci-lint`
Expected: a path is printed; if not, `brew install` runs to completion.

- [ ] **Step 3: Run linter on the (still empty) module**

Run: `cd /Users/domhallan/projects/personal/copyfail-validation && golangci-lint run ./...`
Expected: no output, exit 0. (The module has no Go source yet, so there is nothing to lint and nothing to fail.)

- [ ] **Step 4: Commit**

```bash
git add .golangci.yml
git commit -m "ci: add golangci-lint config with depguard import-graph rules

Enforces the package layering rule from the spec (report is the leaf
of the dependency graph) at lint time. Files in report/ may not import
check, preset, internal, or cmd; files in check/ may not import preset
or cmd. The deny-rule descriptions point future contributors at the
spec section that motivates the constraint."
```

#### Task 0.4: Add Makefile with `lint`, `test`, `cover` targets

**Files:**
- Create: `Makefile`

- [ ] **Step 1: Write Makefile**

Create `/Users/domhallan/projects/personal/copyfail-validation/Makefile`:

```makefile
SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO ?= go
GOLANGCI_LINT ?= golangci-lint
PKG := ./...

.PHONY: help
help: ## List available targets
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run $(PKG)

.PHONY: test
test: ## Run unit tests with race detector
	$(GO) test -race -count=1 $(PKG)

.PHONY: test-integration
test-integration: ## Run integration tests (build tag: integration)
	$(GO) test -race -count=1 -tags=integration $(PKG)

.PHONY: cover
cover: ## Run tests and emit coverage report
	$(GO) test -race -count=1 -coverprofile=cover.out -covermode=atomic $(PKG)
	$(GO) tool cover -func=cover.out | tail -1

.PHONY: cover-html
cover-html: cover ## Open the HTML coverage report in a browser
	$(GO) tool cover -html=cover.out

.PHONY: vuln
vuln: ## Run govulncheck
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

.PHONY: fuzz-kernelmod
fuzz-kernelmod: ## Run kernelmod fuzzers for 30s each
	$(GO) test -fuzz=FuzzParseProcModules -fuzztime=30s ./internal/kernelmod
	$(GO) test -fuzz=FuzzParseModprobeConf -fuzztime=30s ./internal/kernelmod

.PHONY: build
build: ## Build the CLI binary into ./dist
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o dist/copyfail-validate ./cmd/copyfail-validate

.PHONY: clean
clean: ## Remove build artifacts and coverage files
	rm -rf dist cover.out cover.html
```

- [ ] **Step 2: Verify `make help` lists every target**

Run: `cd /Users/domhallan/projects/personal/copyfail-validation && make help`
Expected: every target defined in the Makefile is listed (currently `tidy`, `lint`, `test`, `test-integration`, `cover`, `cover-html`, `vuln`, `fuzz-kernelmod`, `build`, `clean`, `help` — 11 targets at the time of writing; the count is informational only, the assertion is "no target defined in the Makefile is missing from the help output").

- [ ] **Step 3: Verify `make lint` passes on empty module**

Run: `make lint`
Expected: exit 0, no output.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "build: add Makefile with lint, test, cover, vuln, fuzz targets

Single entry point for local development tasks. Mirrors the CI workflow
so 'make lint && make test && make vuln' locally is equivalent to a
green PR check (modulo the e2e job, which runs only on main)."
```

#### Task 0.5: Create CHANGELOG skeleton 🚀 RELEASE BLOCKER

**Files:**
- Create: `CHANGELOG.md`

- [ ] **Step 1: Write skeleton**

Create `/Users/domhallan/projects/personal/copyfail-validation/CHANGELOG.md`:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The JSON output schema (`Report.SchemaVersion`) is versioned **independently**
of the tool. See [`docs/schema.md`](docs/schema.md) for the schema-versioning
contract.

## [Unreleased]

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

[Unreleased]: https://github.com/polyglotdev/copyfail-validation/compare/v0.1.0...HEAD
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add CHANGELOG.md skeleton (Keep-a-Changelog 1.1.0)

Every PR from this point forward updates the [Unreleased] section.
Release tagging promotes [Unreleased] entries under a versioned heading."
```

#### Task 0.6: Create README skeleton 🚀 RELEASE BLOCKER

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write skeleton**

Create `/Users/domhallan/projects/personal/copyfail-validation/README.md`:

```markdown
# copyfail-validation

[![Go Reference](https://pkg.go.dev/badge/github.com/polyglotdev/copyfail-validation.svg)](https://pkg.go.dev/github.com/polyglotdev/copyfail-validation)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> A defensive validator for Linux hosts against the AF_ALG-family kernel-crypto vulnerabilities, starting with **CVE-2026-31431** ("copyfail").

`copyfail-validation` is a static, single-binary Go tool (and reusable library) that checks whether a Linux host has applied the defensive mitigations against the copyfail exploit. It is **read-only** — it never modifies host state, never attempts exploitation, and never executes shell pipelines.

## Quick start

```bash
go install github.com/polyglotdev/copyfail-validation/cmd/copyfail-validate@latest
sudo copyfail-validate
```

## Status

Pre-v0.1.0. Do not depend on the API yet — see [CHANGELOG.md](CHANGELOG.md) for release notes once v0.1.0 ships.

## Documentation

- [Spec](docs/superpowers/specs/2026-05-04-copyfail-validation-design.md)
- [Implementation plan](docs/superpowers/plans/2026-05-04-copyfail-validation-v0.1.md)
- Full README, runbooks, and check catalog land in Phase 7 of the plan.

## License

Apache-2.0. See [LICENSE](LICENSE).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README skeleton with badges and quick start

Phase 7 expands this into the full README (architecture, examples,
SSM runbook link, Prometheus runbook link, security policy link,
contributor guide link). The skeleton exists from Phase 0 so pkg.go.dev
crawls a non-empty README on the first tag."
```

#### Task 0.7: Verify Phase 0 acceptance criteria

- [ ] **Step 1: Run all gates**

Run:
```bash
cd /Users/domhallan/projects/personal/copyfail-validation
make lint && make test && git status
```
Expected:
- `make lint` exits 0 (no Go files yet, but the depguard config is parsed and validated).
- `make test` exits 0 with `?  github.com/polyglotdev/copyfail-validation [no test files]` style messages (or no output if `go test ./...` is happy with an empty module).
- `git status` shows a clean tree.

- [ ] **Step 2: Phase 0 done**

No additional commit. Phase 1 begins.

---

### Phase 1 — Leaf Data Layer

Goal: implement the `report` package (the leaf of the dependency graph) and three small `internal/` helpers that have zero internal dependencies. After Phase 1, `report.Report` can be constructed in tests and serialized to JSON; the `--sign` digest path has its canonical-JSON foundation in place.

**Parallelizable inside Phase 1:** Tasks 1.1–1.7 (`report` package) are sequential among themselves but parallel with tasks 1.8 (`internal/redact`), 1.9 (`internal/buildinfo`), 1.10 (`internal/canonjson`).

#### Task 1.1: report/doc.go — package-level godoc 🚀 RELEASE BLOCKER

**Files:**
- Create: `report/doc.go`

- [ ] **Step 1: Write doc.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package report defines the canonical Report aggregate, the value types
// (State, Severity, Result), and the output Format constants used by the
// copyfail-validation library and CLI.
//
// This package is the leaf of the module's dependency graph: it imports
// nothing else in this module. The check package depends on report;
// preset packages depend on check and report. The directionality is
// enforced at lint time via depguard rules in .golangci.yml.
//
// The Report.SchemaVersion field is versioned independently of the tool
// version; see docs/schema.md for the compatibility contract.
package report
```

- [ ] **Step 2: Verify lint accepts it**

Run: `golangci-lint run ./report/...`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add report/doc.go
git commit -m "feat(report): add package documentation

Establishes the report package as the dependency-graph leaf and
documents the SchemaVersion contract. Future godoc additions to
this package are constrained by the depguard rule that forbids
report from importing anything else in the module."
```

#### Task 1.2: report/state.go — State enum + tests 🚀 RELEASE BLOCKER

**Files:**
- Create: `report/state.go`
- Create: `report/state_test.go`

- [ ] **Step 1: Write the failing test**

Create `report/state_test.go`:

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"encoding/json"
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

func TestState_Constants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  report.State
		want string
	}{
		{"pass", report.StatePass, "pass"},
		{"fail", report.StateFail, "fail"},
		{"skip", report.StateSkip, "skip"},
		{"error", report.StateError, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if string(tt.got) != tt.want {
				t.Errorf("State(%q) = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestState_JSONRoundtrip(t *testing.T) {
	t.Parallel()
	for _, s := range []report.State{report.StatePass, report.StateFail, report.StateSkip, report.StateError} {
		s := s
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got report.State
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got != s {
				t.Errorf("roundtrip: got %q, want %q", got, s)
			}
		})
	}
}

func TestState_SARIFKind(t *testing.T) {
	t.Parallel()
	tests := map[report.State]string{
		report.StatePass:  "pass",
		report.StateFail:  "fail",
		report.StateSkip:  "notApplicable",
		report.StateError: "open",
	}
	for s, want := range tests {
		s, want := s, want
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			if got := s.SARIFKind(); got != want {
				t.Errorf("State(%q).SARIFKind() = %q, want %q", s, got, want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to confirm failure**

Run: `cd /Users/domhallan/projects/personal/copyfail-validation && go test ./report/...`
Expected: FAIL with "report.State undefined" or similar (the package has no symbols yet).

- [ ] **Step 3: Implement state.go**

Create `report/state.go`:

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

// State is the outcome of running a single check.
//
// SARIF mapping (used by the SARIF renderer):
//
//	StatePass  → "pass"
//	StateFail  → "fail"
//	StateSkip  → "notApplicable"
//	StateError → "open"
type State string

// State constants. These string values are part of the JSON wire format
// and are frozen at v1.0.0; renaming or removing one is a major bump per
// docs/superpowers/specs/2026-05-04-copyfail-validation-design.md §5.
const (
	StatePass  State = "pass"
	StateFail  State = "fail"
	StateSkip  State = "skip"
	StateError State = "error"
)

// SARIFKind returns the SARIF v2.1.0 result.kind value corresponding to s.
// Unknown states map to "open" so unexpected values fail safely as
// "result not available" rather than as silent passes.
func (s State) SARIFKind() string {
	switch s {
	case StatePass:
		return "pass"
	case StateFail:
		return "fail"
	case StateSkip:
		return "notApplicable"
	default:
		return "open"
	}
}
```

- [ ] **Step 4: Run test to confirm pass**

Run: `go test ./report/... -v`
Expected: PASS for all subtests.

- [ ] **Step 5: Commit**

```bash
git add report/state.go report/state_test.go
git commit -m "feat(report): add State enum with SARIF mapping

Four states (pass, fail, skip, error) frozen at v1.0.0. SARIFKind()
maps to the SARIF v2.1.0 result.kind values; unknown states map to
'open' for fail-safe behavior."
```

#### Task 1.3: report/severity.go — Severity enum + tests 🚀 RELEASE BLOCKER

**Files:**
- Create: `report/severity.go`
- Create: `report/severity_test.go`

- [ ] **Step 1: Write the failing test**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

func TestSeverity_Constants(t *testing.T) {
	t.Parallel()
	if string(report.SeverityRequired) != "required" {
		t.Errorf("SeverityRequired = %q, want %q", report.SeverityRequired, "required")
	}
	if string(report.SeverityAdvisory) != "advisory" {
		t.Errorf("SeverityAdvisory = %q, want %q", report.SeverityAdvisory, "advisory")
	}
}

func TestSeverity_IsRequired(t *testing.T) {
	t.Parallel()
	if !report.SeverityRequired.IsRequired() {
		t.Error("SeverityRequired.IsRequired() should be true")
	}
	if report.SeverityAdvisory.IsRequired() {
		t.Error("SeverityAdvisory.IsRequired() should be false")
	}
}
```

- [ ] **Step 2: Run test to confirm failure**

Run: `go test ./report/...`
Expected: FAIL with "report.Severity undefined".

- [ ] **Step 3: Implement severity.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

// Severity classifies the operational meaning of a failed check. A failed
// Required check produces a non-zero process exit; a failed Advisory
// check is reported but does not change the exit code.
type Severity string

// Severity constants. Frozen at v1.0.0.
const (
	SeverityRequired Severity = "required"
	SeverityAdvisory Severity = "advisory"
)

// IsRequired reports whether s is SeverityRequired. Defined as a method
// (rather than a direct comparison) so that future Severity values can
// extend the "required-class" set without changing call sites.
func (s Severity) IsRequired() bool {
	return s == SeverityRequired
}
```

- [ ] **Step 4: Run test, confirm pass**

Run: `go test ./report/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add report/severity.go report/severity_test.go
git commit -m "feat(report): add Severity enum with IsRequired helper"
```

#### Task 1.4: report/format.go — Format constants + tests 🚀 RELEASE BLOCKER

**Files:**
- Create: `report/format.go`
- Create: `report/format_test.go`

- [ ] **Step 1: Write the failing test**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

func TestFormat_Constants(t *testing.T) {
	t.Parallel()
	tests := map[report.Format]string{
		report.FormatHuman:      "human",
		report.FormatJSON:       "json",
		report.FormatSARIF:      "sarif",
		report.FormatPrometheus: "prometheus",
	}
	for f, want := range tests {
		if string(f) != want {
			t.Errorf("Format(%q) = %q, want %q", want, f, want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    report.Format
		wantErr bool
	}{
		{"human", report.FormatHuman, false},
		{"HUMAN", report.FormatHuman, false},
		{"json", report.FormatJSON, false},
		{"sarif", report.FormatSARIF, false},
		{"prometheus", report.FormatPrometheus, false},
		{"", "", true},
		{"yaml", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := report.ParseFormat(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./report/...`
Expected: FAIL.

- [ ] **Step 3: Implement format.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"errors"
	"fmt"
	"strings"
)

// Format selects an output renderer.
type Format string

// Format constants. The string values are the canonical CLI flag
// values (case-insensitive on parse; rendered lowercase).
const (
	FormatHuman      Format = "human"
	FormatJSON       Format = "json"
	FormatSARIF      Format = "sarif"
	FormatPrometheus Format = "prometheus"
)

// ErrUnknownFormat is returned by ParseFormat for an unrecognized value.
var ErrUnknownFormat = errors.New("unknown report format")

// ParseFormat converts a case-insensitive flag value into a Format.
// Empty input returns ErrUnknownFormat (callers must explicitly pick a
// format; we do not silently default here).
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "human":
		return FormatHuman, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	case "prometheus":
		return FormatPrometheus, nil
	default:
		return "", fmt.Errorf("%w: %q (want one of: human, json, sarif, prometheus)", ErrUnknownFormat, s)
	}
}
```

- [ ] **Step 4: Pass**

Run: `go test ./report/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add report/format.go report/format_test.go
git commit -m "feat(report): add Format enum + ParseFormat with sentinel error

ParseFormat is case-insensitive but does NOT default — empty input is
an error so the CLI's --format flag handler must explicitly pick a
default based on TTY detection rather than relying on the parser."
```

#### Task 1.5: report/result.go — Result struct + JSON test

**Files:**
- Create: `report/result.go`
- Create: `report/result_test.go`

- [ ] **Step 1: Write the failing test**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/polyglotdev/copyfail-validation/report"
)

func TestResult_JSONShape(t *testing.T) {
	t.Parallel()
	startedAt, _ := time.Parse(time.RFC3339, "2026-05-04T12:34:56Z")
	r := report.Result{
		CheckID:    "modprobe.dry_run",
		Title:      "Modprobe dry-run resolves to /bin/false",
		State:      report.StatePass,
		Severity:   report.SeverityRequired,
		StartedAt:  startedAt,
		DurationMS: 18,
		Detail:     "ok",
		Evidence: map[string]any{
			"command":   "modprobe -n -v algif_aead",
			"exit_code": float64(0),
		},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]any{
		"check_id":    "modprobe.dry_run",
		"title":       "Modprobe dry-run resolves to /bin/false",
		"state":       "pass",
		"severity":    "required",
		"started_at":  "2026-05-04T12:34:56Z",
		"duration_ms": float64(18),
		"detail":      "ok",
		"evidence": map[string]any{
			"command":   "modprobe -n -v algif_aead",
			"exit_code": float64(0),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Result JSON mismatch (-want +got):\n%s", diff)
	}
}

func TestResult_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()
	r := report.Result{
		CheckID:  "x",
		Title:    "y",
		State:    report.StatePass,
		Severity: report.SeverityAdvisory,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, key := range []string{`"detail"`, `"evidence"`, `"error"`} {
		if strings.Contains(s, key) {
			t.Errorf("expected %s to be omitted from %s", key, s)
		}
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./report/...`
Expected: FAIL with "report.Result undefined".

- [ ] **Step 3: Implement result.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

import "time"

// Result is the outcome of one Check execution. The JSON tags are part
// of the public Report.SchemaVersion contract; do not rename without a
// schema major bump (see docs/schema.md).
type Result struct {
	// CheckID is the stable, machine-readable identifier of the check
	// that produced this Result. It appears as the SARIF rule ID and as
	// a Prometheus label value, so it is frozen across schema majors.
	CheckID string `json:"check_id"`

	// Title is a short human-readable name (≤80 chars).
	Title string `json:"title"`

	// State is the outcome category.
	State State `json:"state"`

	// Severity classifies whether a failed Result affects the process exit code.
	Severity Severity `json:"severity"`

	// StartedAt is the wall-clock time the check began. Serialized as
	// RFC3339 with the original timezone offset preserved.
	StartedAt time.Time `json:"started_at"`

	// DurationMS is the elapsed wall-clock time of the check, in milliseconds.
	DurationMS int64 `json:"duration_ms"`

	// Detail is an operator-readable one-line summary. Optional.
	Detail string `json:"detail,omitempty"`

	// Evidence is structured artifacts the check captured (command output,
	// file paths, parsed values). Optional. Implementations should keep
	// values JSON-serializable scalars or maps; nested types must marshal
	// stably across runs.
	Evidence map[string]any `json:"evidence,omitempty"`

	// Err is non-empty iff State == StateError. Holds the operator-readable
	// error message; the wrapped error chain is logged separately via slog.
	Err string `json:"error,omitempty"`
}
```

- [ ] **Step 4: Pass**

Run: `go test ./report/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add report/result.go report/result_test.go
git commit -m "feat(report): add Result struct with JSON shape tests

The JSON tags are part of the public schema contract. Optional fields
use omitempty; required fields (CheckID, Title, State, Severity,
StartedAt, DurationMS) always appear in serialized output."
```

#### Task 1.6: report/report.go — Report + ToolInfo + HostInfo + Summary + Bucket

**Files:**
- Create: `report/report.go`
- Create: `report/report_test.go`

- [ ] **Step 1: Write the failing test**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/polyglotdev/copyfail-validation/report"
)

func TestReport_SummaryComputed(t *testing.T) {
	t.Parallel()
	rep := report.Report{
		SchemaVersion: "1.0.0",
		Tool:          report.ToolInfo{Name: "copyfail-validate", Version: "v0.0.0-test"},
		Host:          report.HostInfo{Hostname: "test-host"},
		Generated:     time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
		Results: []report.Result{
			{CheckID: "a", State: report.StatePass, Severity: report.SeverityRequired},
			{CheckID: "b", State: report.StateFail, Severity: report.SeverityRequired},
			{CheckID: "c", State: report.StateError, Severity: report.SeverityRequired},
			{CheckID: "d", State: report.StateSkip, Severity: report.SeverityAdvisory},
			{CheckID: "e", State: report.StatePass, Severity: report.SeverityAdvisory},
		},
	}
	rep.Summary = report.NewSummary(rep.Results)
	want := report.Summary{
		Total: 5,
		Pass:  2,
		Fail:  1,
		Skip:  1,
		Error: 1,
		Required: report.Bucket{Pass: 1, Fail: 1, Error: 1},
	}
	if diff := cmp.Diff(want, rep.Summary); diff != "" {
		t.Errorf("Summary mismatch (-want +got):\n%s", diff)
	}
}

func TestReport_JSONIncludesSchemaVersion(t *testing.T) {
	t.Parallel()
	rep := report.Report{SchemaVersion: "1.0.0"}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, ok := m["schema_version"].(string); !ok || got != "1.0.0" {
		t.Errorf("schema_version = %v, want \"1.0.0\"", m["schema_version"])
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./report/...`
Expected: FAIL with "report.Report undefined".

- [ ] **Step 3: Implement report.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

import "time"

// SchemaVersionCurrent is the schema version emitted by Report values
// constructed in this build. Bumping this is a major change per
// docs/schema.md.
const SchemaVersionCurrent = "1.0.0"

// Report is the canonical aggregate of a single validator run.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          ToolInfo  `json:"tool"`
	Host          HostInfo  `json:"host"`
	Generated     time.Time `json:"generated_at"`
	Results       []Result  `json:"results"`
	Summary       Summary   `json:"summary"`
}

// ToolInfo describes the build that produced a Report.
type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

// HostInfo describes the host the validator ran against.
type HostInfo struct {
	Hostname      string `json:"hostname"`
	KernelRelease string `json:"kernel_release"`
	OSRelease     string `json:"os_release"`
	OSVersion     string `json:"os_version_id"`
	Arch          string `json:"arch"`
}

// Summary is a tally of Result states across one Report. The Required
// breakdown drives the process exit code (see cmd/copyfail-validate/exit.go
// and the spec §6).
type Summary struct {
	Total    int    `json:"total"`
	Pass     int    `json:"pass"`
	Fail     int    `json:"fail"`
	Skip     int    `json:"skip"`
	Error    int    `json:"error"`
	Required Bucket `json:"required"`
}

// Bucket is the per-severity tally used inside Summary.Required.
// Error is included so callers can compute the exit code without
// re-iterating Results (spec §4 / §6).
type Bucket struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Error int `json:"error"`
}

// NewSummary computes a Summary from a Results slice. Pure function; the
// input slice is not modified.
func NewSummary(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.State {
		case StatePass:
			s.Pass++
		case StateFail:
			s.Fail++
		case StateSkip:
			s.Skip++
		case StateError:
			s.Error++
		}
		if r.Severity.IsRequired() {
			switch r.State {
			case StatePass:
				s.Required.Pass++
			case StateFail:
				s.Required.Fail++
			case StateError:
				s.Required.Error++
			}
			// Required Skip is intentionally NOT tracked separately —
			// a required Skip counts in s.Skip but does not affect the
			// exit code (spec §6: only Required.Fail and Required.Error do).
		}
	}
	return s
}
```

- [ ] **Step 4: Pass**

Run: `go test ./report/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add report/report.go report/report_test.go
git commit -m "feat(report): add Report, ToolInfo, HostInfo, Summary, Bucket

Bucket includes Error so the CLI can compute exit codes from Summary
alone (spec §6). NewSummary is a pure function — Reporters compute
the summary once at the end of a Run rather than maintaining it
incrementally."
```

#### Task 1.7: report/writeto.go — WriteTo stub (real impl in Phase 4)

**Files:**
- Create: `report/writeto.go`
- Create: `report/writeto_test.go`

- [ ] **Step 1: Write the failing test**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

func TestReport_WriteTo_UnknownFormat(t *testing.T) {
	t.Parallel()
	var rep report.Report
	var buf bytes.Buffer
	_, err := rep.WriteTo(&buf, report.Format("yaml"))
	if !errors.Is(err, report.ErrUnknownFormat) {
		t.Errorf("err = %v, want ErrUnknownFormat", err)
	}
}

func TestReport_WriteTo_UnimplementedFormat(t *testing.T) {
	t.Parallel()
	// In Phase 1 the renderers are not yet wired; calling WriteTo with a
	// known format returns ErrRendererNotRegistered. Phase 4 replaces
	// this behavior by registering renderers via init().
	var rep report.Report
	var buf bytes.Buffer
	_, err := rep.WriteTo(&buf, report.FormatJSON)
	if !errors.Is(err, report.ErrRendererNotRegistered) {
		t.Errorf("err = %v, want ErrRendererNotRegistered", err)
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./report/...`
Expected: FAIL.

- [ ] **Step 3: Implement writeto.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// ErrRendererNotRegistered is returned by Report.WriteTo when no renderer
// has been registered for the requested Format. In production builds the
// internal/render package's init() registers all four renderers; tests
// that import only "report" will hit this error.
var ErrRendererNotRegistered = errors.New("no renderer registered for format")

// Renderer writes a Report to w in some format. Registered via Register.
type Renderer func(w io.Writer, rep Report) (int64, error)

var (
	rendererMu sync.RWMutex
	renderers  = map[Format]Renderer{}
)

// Register installs r as the renderer for f. Subsequent calls with the
// same f overwrite the previous renderer (intended for tests; production
// callers should register exactly once via package init).
func Register(f Format, r Renderer) {
	rendererMu.Lock()
	defer rendererMu.Unlock()
	renderers[f] = r
}

// WriteTo writes the Report to w in the given format. Returns the number
// of bytes written and any error from the underlying renderer or writer.
//
// Errors:
//   - ErrUnknownFormat if f is not a recognized Format value.
//   - ErrRendererNotRegistered if f is recognized but no renderer is wired.
//   - Any error returned by the underlying renderer or writer.
func (rep Report) WriteTo(w io.Writer, f Format) (int64, error) {
	switch f {
	case FormatHuman, FormatJSON, FormatSARIF, FormatPrometheus:
		// known format; fall through to renderer lookup
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnknownFormat, string(f))
	}
	rendererMu.RLock()
	r, ok := renderers[f]
	rendererMu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("%w: %q (did you forget to import internal/render?)", ErrRendererNotRegistered, string(f))
	}
	return r(w, rep)
}
```

- [ ] **Step 4: Pass**

Run: `go test ./report/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add report/writeto.go report/writeto_test.go
git commit -m "feat(report): add WriteTo dispatch with renderer registry

Two-stage error model: unknown format (caller bug) and unregistered
renderer (build/import bug). The registry pattern keeps internal/render
out of report's import graph (preserving the depguard rule) while
giving the CLI a single Report.WriteTo entry point. Phase 4 wires the
four renderers via init() in internal/render."
```

#### Task 1.8: internal/redact — secret redactor (parallel with 1.1–1.7) 🚀 RELEASE BLOCKER

**Files:**
- Create: `internal/redact/redact.go`
- Create: `internal/redact/redact_test.go`
- Create: `internal/redact/testdata/positive/aws_access_key.txt`
- Create: `internal/redact/testdata/positive/bearer_token.txt`
- Create: `internal/redact/testdata/positive/db_password.txt`
- Create: `internal/redact/testdata/negative/word_password_in_sentence.txt`
- Create: `internal/redact/testdata/negative/api_key_documentation.txt`

- [ ] **Step 1: Write the failing test**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/redact"
)

func TestRedact_Inline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"aws access key", "aws_access_key_id=AKIAIOSFODNN7EXAMPLE", "aws_access_key_id=***REDACTED***"},
		{"bearer token", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dummy", "Authorization=***REDACTED***"},
		{"password equals", "password=hunter2", "password=***REDACTED***"},
		{"clean string", "modprobe -n -v algif_aead", "modprobe -n -v algif_aead"},
		{"the word password in prose", "Reset your password from the portal", "Reset your password from the portal"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := redact.Redact(tt.in)
			if got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedact_TestdataPositiveCorpus(t *testing.T) {
	t.Parallel()
	matches, err := filepath.Glob("testdata/positive/*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("no positive corpus yet")
	}
	for _, p := range matches {
		p := p
		t.Run(filepath.Base(p), func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			got := redact.Redact(string(b))
			if !strings.Contains(got, "***REDACTED***") {
				t.Errorf("expected ***REDACTED*** in output for %s, got: %s", p, got)
			}
		})
	}
}

func TestRedact_TestdataNegativeCorpus(t *testing.T) {
	t.Parallel()
	matches, err := filepath.Glob("testdata/negative/*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("no negative corpus yet")
	}
	for _, p := range matches {
		p := p
		t.Run(filepath.Base(p), func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			got := redact.Redact(string(b))
			if strings.Contains(got, "***REDACTED***") {
				t.Errorf("did NOT expect redaction in %s, got: %s", p, got)
			}
		})
	}
}
```

- [ ] **Step 2: Create the corpus files**

Create `internal/redact/testdata/positive/aws_access_key.txt`:
```
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Create `internal/redact/testdata/positive/bearer_token.txt`:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature
```

Create `internal/redact/testdata/positive/db_password.txt`:
```
postgres://user:password=mySecret123@db.example.internal:5432/app
```

Create `internal/redact/testdata/negative/word_password_in_sentence.txt`:
```
Reset your password from the portal
The password reset link is sent via email
```

Create `internal/redact/testdata/negative/api_key_documentation.txt`:
```
See the API key documentation at https://example.com/docs/api-keys
The default api key permissions are read-only
```

- [ ] **Step 3: Run, fail**

Run: `go test ./internal/redact/...`
Expected: FAIL with "redact.Redact undefined".

- [ ] **Step 4: Implement redact.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package redact removes secret-like substrings from text destined for
// audit reports. The single regex is tuned for high precision over high
// recall: false positives in operator-facing output would be more
// disruptive than the rare missed redaction.
package redact

import "regexp"

// RedactionPattern matches `keyword=VALUE` or `keyword: VALUE` shapes
// where keyword is one of the listed secret labels (case-insensitive).
// The keyword is preserved in the output; the value is replaced with
// ***REDACTED***.
const RedactionPattern = `(?i)(password|passwd|token|secret|bearer|api[_-]?key|aws_(?:access|secret)_key_id?|authorization)\s*[:=]\s*\S+`

// Replacement is the substring written in place of the matched value.
const Replacement = "***REDACTED***"

var pattern = regexp.MustCompile(RedactionPattern)

// Redact returns s with secret-like substrings replaced. Safe to call on
// large strings; the regex is anchored so worst-case complexity is
// O(len(s)).
func Redact(s string) string {
	return pattern.ReplaceAllStringFunc(s, func(match string) string {
		// Find the keyword (everything up to the first separator).
		for i, r := range match {
			if r == '=' || r == ':' {
				return match[:i] + "=" + Replacement
			}
		}
		return Replacement
	})
}
```

- [ ] **Step 5: Pass**

Run: `go test ./internal/redact/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/redact/
git commit -m "feat(redact): add Redact() with pattern + corpus

Single regex per spec §7, lifted out of the markdown table to a Go
const so the implementation reads identically to the spec. Positive
and negative corpus files demonstrate the precision/recall tradeoff:
keyword inside running prose ('reset your password') is intentionally
NOT redacted."
```

#### Task 1.9: internal/buildinfo — version/commit/build-date stamping (parallel)

**Files:**
- Create: `internal/buildinfo/buildinfo.go`
- Create: `internal/buildinfo/buildinfo_test.go`

- [ ] **Step 1: Write the failing test**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package buildinfo_test

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
)

func TestVarsHaveDefaults(t *testing.T) {
	t.Parallel()
	if buildinfo.Version == "" {
		t.Error("Version must have a non-empty default")
	}
	if buildinfo.Commit == "" {
		t.Error("Commit must have a non-empty default")
	}
	if buildinfo.BuildDate == "" {
		t.Error("BuildDate must have a non-empty default")
	}
}

func TestInfo_PopulatesToolInfo(t *testing.T) {
	t.Parallel()
	info := buildinfo.Info()
	if info.Name == "" {
		t.Error("Info().Name should be non-empty")
	}
	if info.Version != buildinfo.Version {
		t.Errorf("Info().Version = %q, want %q", info.Version, buildinfo.Version)
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./internal/buildinfo/...`
Expected: FAIL.

- [ ] **Step 3: Implement buildinfo.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo holds build-time-injected version metadata. The
// Version, Commit, and BuildDate vars are overridden at link time via
// -ldflags="-X github.com/polyglotdev/copyfail-validation/internal/buildinfo.Version=...".
// Defaults exist so `go run` and `go test` produce non-empty values.
package buildinfo

import "github.com/polyglotdev/copyfail-validation/report"

// ToolName is the canonical binary name. Not overridable.
const ToolName = "copyfail-validate"

// Build-time-injected metadata. Overridden by goreleaser via -ldflags.
var (
	Version   = "v0.0.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info returns a report.ToolInfo populated from the package vars.
func Info() report.ToolInfo {
	return report.ToolInfo{
		Name:      ToolName,
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
	}
}
```

- [ ] **Step 4: Pass**

Run: `go test ./internal/buildinfo/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/buildinfo/
git commit -m "feat(buildinfo): add ldflags-injected Version/Commit/BuildDate

Defaults of v0.0.0-dev / unknown / unknown ensure 'go run' and 'go test'
produce non-empty output without needing the goreleaser -ldflags. Info()
returns a report.ToolInfo so cmd/copyfail-validate can populate
report.Tool with one call."
```

#### Task 1.10: internal/canonjson — RFC 8785 (JCS) canonicalizer (parallel)

**Files:**
- Create: `internal/canonjson/canonjson.go`
- Create: `internal/canonjson/canonjson_test.go`
- Create: `internal/canonjson/testdata/rfc8785_testvectors.json` (subset)

- [ ] **Step 1: Write the failing test**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package canonjson_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/canonjson"
)

func TestCanonicalize_SortsKeys(t *testing.T) {
	t.Parallel()
	in := []byte(`{"b":1,"a":2,"c":{"y":3,"x":4}}`)
	got, err := canonjson.Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1,"c":{"x":4,"y":3}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalize_StripsWhitespace(t *testing.T) {
	t.Parallel()
	in := []byte("{\n  \"a\": 1,\n  \"b\": 2\n}")
	got, err := canonjson.Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":1,"b":2}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSHA256_Stable(t *testing.T) {
	t.Parallel()
	a := []byte(`{"a":1,"b":2}`)
	b := []byte(`{"b": 2, "a": 1}`)
	ha, err := canonjson.SHA256(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := canonjson.SHA256(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Errorf("equivalent JSON produced different hashes:\n  a: %s\n  b: %s", ha, hb)
	}
	// sanity: length is 64 hex chars
	if len(ha) != 2*sha256.Size {
		t.Errorf("hash length = %d, want %d", len(ha), 2*sha256.Size)
	}
	// sanity: hex-decodable
	if _, err := hex.DecodeString(ha); err != nil {
		t.Errorf("hash not hex: %v", err)
	}
	// (the sample JSON IS valid; this assertion just exercises encoding/json so the
	// import isn't unused if the implementation switches strategies)
	var v any
	if err := json.Unmarshal(a, &v); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./internal/canonjson/...`
Expected: FAIL.

- [ ] **Step 3: Implement canonjson.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package canonjson implements a subset of RFC 8785 (JSON Canonicalization
// Scheme) sufficient for producing reproducible SHA-256 digests of
// validator reports. The full RFC 8785 number-canonicalization rules
// (ECMAScript 6 numeric serialization, exponent normalization) are NOT
// implemented because the Report schema only emits integers and strings —
// no floating-point. If a future schema major adds floats, this package
// must be revisited; a regression test pins the current behavior.
package canonjson

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalize returns the canonical JSON form of in per the rules above:
// UTF-8, sorted object keys at every level, no insignificant whitespace,
// integers without trailing decimals.
func Canonicalize(in []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber() // preserve integer-ness; avoid float64 round-tripping
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonjson: decode: %w", err)
	}
	var buf bytes.Buffer
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SHA256 returns the lowercase-hex SHA-256 digest of Canonicalize(in).
func SHA256(in []byte) (string, error) {
	c, err := Canonicalize(in)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

func write(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(string(x))
	case string:
		b, err := json.Marshal(x) // delegate to stdlib for escape rules per RFC 8259 §7
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // RFC 8785 §3.2.3: sort by code-unit values; ASCII keys → byte-sort works
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := write(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonjson: unsupported type %T", v)
	}
	return nil
}
```

- [ ] **Step 4: Pass**

Run: `go test ./internal/canonjson/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/canonjson/
git commit -m "feat(canonjson): add RFC 8785 JCS canonicalizer (subset)

Implements the subset needed for stable Report digests: sorted object
keys at every level, no whitespace, json.Number preservation. The full
RFC 8785 numeric-canonicalization rules are out of scope while the
Report schema avoids floats; the package doc captures this caveat
and a regression test will catch it if the schema ever adds them."
```

#### Task 1.11: Verify Phase 1 acceptance criteria 🚀 RELEASE BLOCKER

- [ ] **Step 1: Run full test + lint**

Run:
```bash
cd /Users/domhallan/projects/personal/copyfail-validation
make lint && make test
```
Expected:
- lint exits 0 (golangci-lint runs clean on the new packages, including depguard).
- All tests pass.

- [ ] **Step 2: Verify the depguard rule actually fires**

Create a temporary file `report/_violation.go.disabled` (the `.disabled` suffix keeps it out of the build):

```go
// Manually rename to .go and run `make lint` to verify the rule fires.
// Expected: depguard error: "report is the leaf of the dependency graph; ..."
package report

import _ "github.com/polyglotdev/copyfail-validation/check"
```

Then:
```bash
mv report/_violation.go.disabled report/_violation.go
make lint || echo "DEPGUARD FIRED: rule works"
mv report/_violation.go report/_violation.go.disabled
```
Expected: lint fails with the depguard error message; manual confirmation only — do not commit the file.

- [ ] **Step 3: Phase 1 done**

```bash
rm report/_violation.go.disabled
git status   # confirm clean tree
```

---

## Chunk 2: Internal Helpers (Phase 2)

### Phase 2 — Internal Helpers

Goal: build the safe-subprocess wrapper, the kernel-module / `/proc` parsers, the package-manager backends, the `/proc/<pid>/maps` scanner for AF_ALG, and the small support packages (`hostinfo`, `logging`). After Phase 2, every behavioral primitive the `check` package needs in Phase 3 exists, is tested, and runs without ever invoking a shell.

**Sequencing:**

1. **Task 2.1 (`internal/exec`)** must complete first — `kernelmod` and `integrity` import it.
2. After 2.1, tasks **2.2–2.7** can run in parallel (each in its own session/worktree if you're parallelizing across humans or subagents).

#### Task 2.1: internal/exec — safe subprocess wrapper 🚀 RELEASE BLOCKER

This task is the largest in Phase 2 because it carries the security model. Reference `cc-skills-golang:golang-security` and `cc-skills-golang:golang-design-patterns` while working it.

**Files:**
- Create: `internal/exec/arg.go`
- Create: `internal/exec/arg_test.go`
- Create: `internal/exec/allowlist.go`
- Create: `internal/exec/allowlist_test.go`
- Create: `internal/exec/errors.go`
- Create: `internal/exec/cmd.go`
- Create: `internal/exec/cmd_test.go`
- Create: `internal/exec/runner.go`
- Create: `internal/exec/runner_test.go`
- Create: `internal/exec/helper_test.go` (TestHelperProcess pattern)

##### Subtask 2.1.a: Arg interface (Trusted/Untrusted typing)

- [ ] **Step 1: Write the failing test**

`internal/exec/arg_test.go`:

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"errors"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

func TestArg_TrustedAlwaysValid(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "anything goes; rm -rf /", "../../etc/shadow", "--flag=value"} {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			if err := exec.Validate(exec.Trusted(s)); err != nil {
				t.Errorf("Trusted(%q) should always validate, got %v", s, err)
			}
		})
	}
}

func TestArg_UntrustedAcceptsSafeChars(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"algif_aead", "util-linux-core-2.39.4-7.amzn2023.x86_64", "/usr/bin/su", "v1.2.3"} {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			if err := exec.Validate(exec.Untrusted(s)); err != nil {
				t.Errorf("Untrusted(%q) should validate, got %v", s, err)
			}
		})
	}
}

func TestArg_UntrustedRejectsDangerousChars(t *testing.T) {
	t.Parallel()
	tests := []string{
		"foo;rm -rf /",
		"foo bar",                // space
		"foo$BAR",                // shell variable expansion
		"foo`whoami`",            // command substitution
		"foo|cat",                // pipe
		"foo>out",                // redirect
		"foo\nbar",               // newline
		"foo\x00bar",             // NUL
		"--config=/etc/passwd",   // leading dash
		"-rf",                    // leading dash
		"",                       // empty
	}
	for _, s := range tests {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			err := exec.Validate(exec.Untrusted(s))
			if !errors.Is(err, exec.ErrInvalidArg) {
				t.Errorf("Untrusted(%q) should be rejected, got %v", s, err)
			}
		})
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./internal/exec/...`
Expected: FAIL.

- [ ] **Step 3: Implement arg.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"fmt"
	"regexp"
	"strings"
)

// Arg is the argument-slot type accepted by Cmd.Args. Concrete types
// are Trusted (bypasses character validation) and Untrusted (must pass
// UntrustedArgRE and not begin with a dash). New Arg implementations
// MUST go through security review — the Arg interface is sealed via
// the unexported argSentinel method.
type Arg interface {
	argSentinel()
	String() string
}

// Trusted is a string the caller asserts is safe — typically a constant
// or a value validated by a domain-specific validator (e.g., a path
// already cleaned by the --conf flag handler). Validate always returns
// nil for Trusted values.
type Trusted string

func (Trusted) argSentinel()    {}
func (t Trusted) String() string { return string(t) }

// Untrusted is a string from a user-controlled source (flag, env var,
// subprocess output that will be re-fed to another subprocess). It MUST
// pass Validate before being placed in a Cmd.Args slot.
type Untrusted string

func (Untrusted) argSentinel()    {}
func (u Untrusted) String() string { return string(u) }

// UntrustedArgRE matches the conservative set of characters allowed in
// an Untrusted argument: alphanumerics, dot, underscore, hyphen, forward
// slash, plus, colon, equals, comma, at-sign. Length must be ≥ 1.
//
// NOTE: this regex deliberately permits forward slash (legitimate values
// include package names and absolute paths) and does NOT block ".."
// segments — that is the caller's responsibility (path-traversal defense
// belongs to the layer that knows path semantics; see spec §7).
//
// Leading "-" is rejected by a separate check below to prevent flag
// injection (e.g., `--config=/etc/passwd` masquerading as a positional).
var UntrustedArgRE = regexp.MustCompile(`^[A-Za-z0-9._\-/+:=,@]+$`)

// Validate reports whether arg is acceptable for Cmd.Args. Trusted args
// always pass; Untrusted args must match UntrustedArgRE and not start
// with a dash.
func Validate(arg Arg) error {
	switch a := arg.(type) {
	case Trusted:
		return nil
	case Untrusted:
		s := string(a)
		if !UntrustedArgRE.MatchString(s) {
			return fmt.Errorf("%w: %q (allowed: %s)", ErrInvalidArg, s, UntrustedArgRE.String())
		}
		if strings.HasPrefix(s, "-") {
			return fmt.Errorf("%w: %q starts with '-' (flag-injection guard)", ErrInvalidArg, s)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown Arg type %T", ErrInvalidArg, arg)
	}
}
```

Create `internal/exec/errors.go`:

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import "errors"

// Sentinel errors returned by this package. Callers should match with
// errors.Is rather than string comparison.
var (
	// ErrCommandNotFound is returned when the requested command name is not
	// in allowedCommands and is not found via exec.LookPath.
	ErrCommandNotFound = errors.New("exec: command not found")

	// ErrCommandDenied is returned when the requested command name is not
	// in allowedCommands. (Distinct from ErrCommandNotFound: the binary
	// might exist on PATH but isn't on our allowlist.)
	ErrCommandDenied = errors.New("exec: command not on allowlist")

	// ErrInvalidArg is returned when an Untrusted arg fails validation.
	ErrInvalidArg = errors.New("exec: invalid argument")

	// ErrTimeout is returned when the per-Cmd timeout fires.
	ErrTimeout = errors.New("exec: command timed out")

	// ErrOutputTruncated wraps the returned error when stdout or stderr
	// exceeded MaxOutput bytes; the truncated bytes are still in Result.
	ErrOutputTruncated = errors.New("exec: output truncated")
)
```

- [ ] **Step 4: Pass**

Run: `go test ./internal/exec/... -v -run TestArg`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/exec/arg.go internal/exec/arg_test.go internal/exec/errors.go
git commit -m "feat(exec): add Trusted/Untrusted Arg interface + sentinel errors

Type-system enforcement of the trust boundary: every Cmd.Args slot
must be a Trusted or Untrusted value, and Untrusted values are
character-validated and flag-injection-checked before exec. Sealed
via unexported argSentinel() so external packages can't add a third
trust class without security review."
```

##### Subtask 2.1.b: allowlist (allowedCommands map)

- [ ] **Step 1: Write the failing test**

`internal/exec/allowlist_test.go`:

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"errors"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

func TestResolveCommand_AllowlistedAbsolutePath(t *testing.T) {
	t.Parallel()
	// uname is allowlisted; on macOS dev machines and Linux CI runners,
	// /usr/bin/uname or /bin/uname exists. We don't assert which path —
	// only that resolution succeeds AND the returned path is one of the
	// allowlisted absolute paths or a PATH-resolved fallback.
	got, err := exec.ResolveCommand("uname")
	if err != nil {
		t.Fatalf("ResolveCommand(uname): %v", err)
	}
	if got == "" {
		t.Errorf("expected non-empty path")
	}
}

func TestResolveCommand_DeniedCommand(t *testing.T) {
	t.Parallel()
	_, err := exec.ResolveCommand("rm")
	if !errors.Is(err, exec.ErrCommandDenied) {
		t.Errorf("err = %v, want ErrCommandDenied", err)
	}
}

func TestResolveCommand_AllowlistedButNotInstalled(t *testing.T) {
	t.Parallel()
	// debsums is allowlisted but isn't installed on macOS or default
	// Linux containers. We accept either error — the contract is that
	// it must NOT return a misleading path.
	_, err := exec.ResolveCommand("debsums")
	if err == nil {
		t.Skip("debsums is installed on this host; cannot test the not-installed path")
	}
	if !errors.Is(err, exec.ErrCommandNotFound) && !errors.Is(err, exec.ErrCommandDenied) {
		t.Errorf("unexpected err type: %v", err)
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./internal/exec/... -run TestResolveCommand`
Expected: FAIL.

- [ ] **Step 3: Implement allowlist.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"fmt"
	osexec "os/exec"
	"os"
)

// allowedCommands maps logical command name → preferred absolute path.
// Lookup falls back to exec.LookPath only if the absolute path is missing.
// Adding a new entry requires security review.
var allowedCommands = map[string]string{
	"modprobe":   "/sbin/modprobe",
	"lsmod":      "/sbin/lsmod",
	"uname":      "/bin/uname",
	"rpm":        "/usr/bin/rpm",
	"dpkg":       "/usr/bin/dpkg",
	"dpkg-query": "/usr/bin/dpkg-query",
	"debsums":    "/usr/bin/debsums",
	"sha256sum":  "/usr/bin/sha256sum",
}

// ResolveCommand returns the absolute path to execute for the logical
// command name, or an error. ErrCommandDenied if name is not allowlisted;
// ErrCommandNotFound if it's allowlisted but neither the preferred path
// exists nor PATH lookup succeeds.
func ResolveCommand(name string) (string, error) {
	preferred, ok := allowedCommands[name]
	if !ok {
		return "", fmt.Errorf("%w: %q (add to allowedCommands with security review)", ErrCommandDenied, name)
	}
	if _, err := os.Stat(preferred); err == nil {
		return preferred, nil
	}
	resolved, err := osexec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: %q (preferred=%s, PATH lookup failed: %v)", ErrCommandNotFound, name, preferred, err)
	}
	return resolved, nil
}
```

- [ ] **Step 4: Pass**

Run: `go test ./internal/exec/... -v -run TestResolveCommand`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/exec/allowlist.go internal/exec/allowlist_test.go
git commit -m "feat(exec): add allowlist + ResolveCommand

Eight entries matching spec §7 (lsof intentionally omitted — see
spec §11 for the AF_ALG check that replaced it). ResolveCommand
prefers the allowlisted absolute path but falls back to PATH lookup
so the binary works on unusual distros where modprobe lives in
/usr/sbin instead of /sbin."
```

##### Subtask 2.1.c: Cmd, Result, Run

- [ ] **Step 1: Write the failing test (uses TestHelperProcess pattern)**

`internal/exec/helper_test.go`:

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"fmt"
	"os"
	"testing"
)

// TestHelperProcess is invoked by subtests that re-exec the test binary
// with -test.run=TestHelperProcess to simulate a subprocess. This is the
// stdlib pattern used in os/exec's own tests.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)
	switch os.Getenv("GO_HELPER_BEHAVIOR") {
	case "echo-stdout":
		fmt.Print(os.Getenv("GO_HELPER_TEXT"))
	case "echo-stderr":
		fmt.Fprint(os.Stderr, os.Getenv("GO_HELPER_TEXT"))
	case "exit-nonzero":
		os.Exit(2)
	case "sleep-forever":
		select {}
	}
}
```

`internal/exec/cmd_test.go`:

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// withHelperRunner returns an exec.Runner that invokes this test binary
// as a subprocess with the helper-process sentinel env vars set. Lets us
// exercise real syscalls without depending on host binaries.
func withHelperRunner(t *testing.T, behavior, text string) exec.Runner {
	t.Helper()
	return exec.NewRunnerForTest(os.Args[0], []string{"-test.run=TestHelperProcess", "--"}, []string{
		"GO_WANT_HELPER_PROCESS=1",
		"GO_HELPER_BEHAVIOR=" + behavior,
		"GO_HELPER_TEXT=" + text,
	})
}

func TestCmd_Run_CapturesStdout(t *testing.T) {
	t.Parallel()
	r := withHelperRunner(t, "echo-stdout", "hello world")
	res, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname", // logical name; runner ignores in test mode
		Args:    []exec.Arg{exec.Trusted("-r")},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Stdout) != "hello world" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "hello world")
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
}

func TestCmd_Run_TimesOut(t *testing.T) {
	t.Parallel()
	r := withHelperRunner(t, "sleep-forever", "")
	_, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{},
		Timeout: 100 * time.Millisecond,
	})
	if !errors.Is(err, exec.ErrTimeout) {
		t.Errorf("err = %v, want ErrTimeout", err)
	}
}

func TestCmd_Run_RejectsInvalidArg(t *testing.T) {
	t.Parallel()
	r := withHelperRunner(t, "echo-stdout", "")
	_, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{exec.Untrusted("foo;rm -rf /")},
		Timeout: 2 * time.Second,
	})
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Errorf("err = %v, want ErrInvalidArg", err)
	}
}
```

- [ ] **Step 2: Run, fail**

Run: `go test ./internal/exec/...`
Expected: FAIL with "exec.NewRunnerForTest undefined" / "exec.Cmd undefined".

- [ ] **Step 3: Implement cmd.go**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import "time"

// MaxOutput is the per-stream cap on captured stdout/stderr (1 MiB).
// Exceeding output is truncated; Result.Truncated is set to true.
const MaxOutput = 1 << 20

// DefaultTimeout is applied when Cmd.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// Cmd describes one command to execute. The zero Cmd is invalid;
// callers MUST set Name and SHOULD set Timeout.
type Cmd struct {
	// Name is the logical command name (e.g., "modprobe"). Resolved via
	// ResolveCommand at Run time.
	Name string

	// Args are the command arguments. Each must be a Trusted or Untrusted
	// value (see arg.go). Untrusted args are validated before exec.
	Args []Arg

	// Timeout is the maximum wall-clock duration. Zero means DefaultTimeout.
	Timeout time.Duration

	// Env, if non-nil, replaces the inherited environment. Default behavior
	// (Env == nil) uses a minimal env: PATH from the parent and LANG=C.
	Env []string
}

// Result holds what a Cmd.Run captured.
type Result struct {
	Stdout    []byte
	Stderr    []byte
	Truncated bool
	ExitCode  int
	Path      string // resolved absolute path of the executable that ran
	Duration  time.Duration
}
```

`internal/exec/runner.go`:

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"time"
)

// Runner executes a Cmd. The production implementation is osRunner;
// tests use FakeRunner.
type Runner interface {
	Run(ctx context.Context, cmd Cmd) (Result, error)
}

// NewOSRunner returns the production Runner that uses os/exec.
func NewOSRunner() Runner { return osRunner{} }

// NewRunnerForTest returns a Runner that always invokes argv0 with
// prefixedArgs ++ cmd.Args (after stringification) and the given env.
// This drives the TestHelperProcess pattern; not for production use.
func NewRunnerForTest(argv0 string, prefixedArgs, env []string) Runner {
	return &testRunner{argv0: argv0, prefix: prefixedArgs, env: env}
}

// FakeRunner returns canned Results from a map keyed by `cmd.Name + " " + strings.Join(args, " ")`.
type FakeRunner struct {
	Responses map[string]Result
	Errors    map[string]error
	Calls     []Cmd
}

func (f *FakeRunner) Run(_ context.Context, cmd Cmd) (Result, error) {
	f.Calls = append(f.Calls, cmd)
	key := cmd.Name
	for _, a := range cmd.Args {
		key += " " + a.String()
	}
	if err, ok := f.Errors[key]; ok {
		return Result{}, err
	}
	if r, ok := f.Responses[key]; ok {
		return r, nil
	}
	return Result{}, fmt.Errorf("FakeRunner: no response registered for %q", key)
}

// osRunner is the production implementation.
type osRunner struct{}

func (osRunner) Run(ctx context.Context, cmd Cmd) (Result, error) {
	path, err := ResolveCommand(cmd.Name)
	if err != nil {
		return Result{}, err
	}
	return runResolved(ctx, path, cmd)
}

// testRunner re-execs the test binary with a sentinel env to simulate a subprocess.
type testRunner struct {
	argv0  string
	prefix []string
	env    []string
}

func (t *testRunner) Run(ctx context.Context, cmd Cmd) (Result, error) {
	for _, a := range cmd.Args {
		if err := Validate(a); err != nil {
			return Result{}, err
		}
	}
	timeout := cmd.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := append([]string{}, t.prefix...)
	for _, a := range cmd.Args {
		args = append(args, a.String())
	}
	c := osexec.CommandContext(ctx, t.argv0, args...)
	c.Env = t.env
	return runProcess(ctx, c, t.argv0)
}

func runResolved(ctx context.Context, path string, cmd Cmd) (Result, error) {
	for _, a := range cmd.Args {
		if err := Validate(a); err != nil {
			return Result{}, err
		}
	}
	timeout := cmd.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := make([]string, 0, len(cmd.Args))
	for _, a := range cmd.Args {
		args = append(args, a.String())
	}
	c := osexec.CommandContext(ctx, path, args...)
	if cmd.Env != nil {
		c.Env = cmd.Env
	} else {
		c.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C"}
	}
	return runProcess(ctx, c, path)
}

func runProcess(ctx context.Context, c *osexec.Cmd, path string) (Result, error) {
	stdout, stderr := &cappedBuffer{cap: MaxOutput}, &cappedBuffer{cap: MaxOutput}
	c.Stdout = stdout
	c.Stderr = stderr
	start := time.Now()
	err := c.Run()
	dur := time.Since(start)
	res := Result{
		Stdout:    stdout.bytes,
		Stderr:    stderr.bytes,
		Truncated: stdout.truncated || stderr.truncated,
		Path:      path,
		Duration:  dur,
	}
	if c.ProcessState != nil {
		res.ExitCode = c.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%w: after %s", ErrTimeout, dur)
	}
	if err != nil {
		var ee *osexec.ExitError
		if errors.As(err, &ee) {
			// non-zero exit; surface ExitCode to caller, return wrapped error
			return res, fmt.Errorf("exec %s: %w", path, err)
		}
		return res, fmt.Errorf("exec %s: %w", path, err)
	}
	if res.Truncated {
		return res, ErrOutputTruncated
	}
	return res, nil
}

// cappedBuffer is an io.Writer that stops collecting after cap bytes.
type cappedBuffer struct {
	cap       int
	bytes     []byte
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.truncated {
		return len(p), nil // pretend we wrote it; subprocess may keep producing
	}
	remaining := b.cap - len(b.bytes)
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.bytes = append(b.bytes, p[:remaining]...)
		b.truncated = true
		return len(p), nil
	}
	b.bytes = append(b.bytes, p...)
	return len(p), nil
}

// ensure cappedBuffer satisfies io.Writer
var _ io.Writer = (*cappedBuffer)(nil)
```

- [ ] **Step 4: Pass**

Run: `go test ./internal/exec/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/exec/cmd.go internal/exec/runner.go internal/exec/cmd_test.go internal/exec/helper_test.go
git commit -m "feat(exec): add Cmd, Result, and three Runner implementations

osRunner is production; testRunner enables the TestHelperProcess pattern;
FakeRunner is for unit tests of higher layers. cappedBuffer enforces the
1 MiB output limit per stream by quietly dropping excess (subprocess
keeps running; we avoid SIGPIPE-via-closed-stdout)."
```

---

> **End of inline-code section.** Phases 0–1 and the security-critical `internal/exec` (Task 2.1) carry full inline implementations because they set patterns the rest of the codebase follows. Phases 2.2–8.x below are written in **task-skeleton form**: file paths, key signatures, test focus, acceptance criteria, and commit messages — but not full inline code. Subagents implementing these tasks read the neighboring already-implemented files for style and patterns. This is intentional per the writing-plans skill's guidance to avoid plan bloat without losing actionability.

---

#### Task 2.2: internal/kernelmod — /proc/modules parser 🚀 RELEASE BLOCKER

**Files:** `internal/kernelmod/procmodules.go`, `internal/kernelmod/procmodules_test.go`, `internal/kernelmod/procmodules_fuzz_test.go`

**Skill:** `cc-skills-golang:golang-testing` (table-driven + fuzz patterns)

**Public surface:**
```go
type LoadedModule struct {
    Name     string
    Size     int64
    RefCount int
    UsedBy   []string
    State    string // "Live", "Loading", "Unloading"
}
func ParseProcModules(r io.Reader) ([]LoadedModule, error)
func IsLoaded(modules []LoadedModule, name string) bool
var ErrMalformed = errors.New("kernelmod: malformed /proc/modules line")
```

**Test focus:**
- Real `/proc/modules` sample committed to `internal/kernelmod/testdata/procmodules-al2023.txt` (anonymize: zero out kernel addresses).
- Sample with `algif_aead 16384 0 - Live 0xffffffff...` → `IsLoaded("algif_aead")` returns true.
- Sample without algif → returns false.
- Empty file → empty slice, no error.
- Single malformed line → returns `ErrMalformed` for that line; well-formed lines before/after still parsed.
- Fuzz: `FuzzParseProcModules` seeded with the testdata file + `""` + a few random strings.

**Acceptance:** `go test -race ./internal/kernelmod/...` passes; `make fuzz-kernelmod` runs 30s without panics.

- [ ] Step 1: Write failing test
- [ ] Step 2: Implement parser
- [ ] Step 3: Add fuzz test
- [ ] Step 4: Verify all pass with race detector
- [ ] Step 5: Commit `feat(kernelmod): add /proc/modules parser`

#### Task 2.3: internal/kernelmod — modprobe.d *.conf parser 🚀 RELEASE BLOCKER

**Files:** `internal/kernelmod/conf.go`, `internal/kernelmod/conf_test.go`, `internal/kernelmod/conf_fuzz_test.go`

**Public surface:**
```go
type ConfDirective struct {
    Kind    string // "install", "blacklist", "options", "alias"
    Module  string
    Args    []string // remainder of the line after the module name
    Source  string // file path
    LineNum int
}
func ParseConfFile(path string) ([]ConfDirective, error)
func ParseConfDir(dir string) ([]ConfDirective, error)  // alphabetical scan; later files override earlier per modprobe semantics
func InstallTarget(directives []ConfDirective, module string) (target string, found bool)
func IsBlacklisted(directives []ConfDirective, module string) bool
```

**Test focus:**
- Golden file with `install algif_aead /bin/false` + `blacklist algif_aead` → parses both directives.
- Comment lines (`#`) and blank lines ignored.
- `\` line continuation handled (modprobe supports it).
- Symlink-followed `O_NOFOLLOW` audit (per spec §7): if path is a symlink, the parser logs the target in a returned `Source` field but proceeds.
- Multi-file scan: `00-blacklist.conf` says `install … /bin/false`, `99-override.conf` says `install … /bin/true` → `InstallTarget` returns `/bin/true` (later wins, matching modprobe's actual behavior — this is exactly what `modprobe.dependency_chain` exists to detect).

**Acceptance:** parser handles realistic conf samples from AL2023 and Ubuntu 22.04 (commit anonymized samples to `testdata/`).

- [ ] Step 1-5: TDD cycle, commit `feat(kernelmod): add /etc/modprobe.d parser with override-aware scan`

#### Task 2.4: internal/kernelmod — modprobe -nv invocation parser

**Files:** `internal/kernelmod/modprobe.go`, `internal/kernelmod/modprobe_test.go`

**Public surface:**
```go
type DryRun struct {
    ResolvedTo  string   // e.g., "/bin/false" if blocked, "/sbin/insmod /lib/modules/.../algif_aead.ko" if loadable
    BlockedBy   string   // file path of the conf entry that produced /bin/false; empty if not blocked
    RawOutput   string
}
func DryRunModule(ctx context.Context, runner exec.Runner, module string) (DryRun, error)
```

**Test focus:**
- Use `FakeRunner` to feed canned `modprobe -nv` output samples (one for the blocked case, one for the loadable case).
- Verify `ResolvedTo == "/bin/false"` for the blocked sample.
- Verify the function does NOT actually shell out (the FakeRunner records the call; assert `Calls[0].Args == []Arg{Trusted("-n"), Trusted("-v"), Untrusted("algif_aead")}`).
- Argument injection: `DryRunModule(ctx, r, "algif;rm -rf /")` returns `ErrInvalidArg` (the module name is wrapped in `Untrusted` and validation rejects it).

**Acceptance:** zero shell invocations; structured types only.

- [ ] Step 1-5: TDD cycle, commit `feat(kernelmod): add safe modprobe -nv wrapper`

#### Task 2.5: internal/integrity — pkgmgr interface + Detect 🚀 RELEASE BLOCKER

**Files:** `internal/integrity/pkgmgr.go`, `internal/integrity/pkgmgr_test.go`, `internal/integrity/rpm.go`, `internal/integrity/rpm_test.go`, `internal/integrity/dpkg.go`, `internal/integrity/dpkg_test.go`

**Skill:** `cc-skills-golang:golang-security`, `cc-skills-golang:golang-design-patterns` (interface-with-Detect pattern, like `database/sql` drivers)

**Public surface:**
```go
type PkgMgr interface {
    Name() string  // "rpm" or "dpkg"
    OwnerOf(ctx context.Context, runner exec.Runner, path string) (pkg string, err error)
    Verify(ctx context.Context, runner exec.Runner, pkg string) (VerifyResult, error)
}

type VerifyResult struct {
    Path           string
    HashMatches    bool
    HashMismatch   bool
    MTimeChanged   bool
    SizeChanged    bool
    PermsChanged   bool
    OwnerChanged   bool
    GroupChanged   bool
    UnverifiedReasons []string
    RawOutput      string
}

// Detect picks an available pkgmgr by checking which ResolveCommand calls succeed.
// Returns ErrNoPkgManager if neither rpm nor dpkg is available.
func Detect(runner exec.Runner) (PkgMgr, error)

var ErrNoPkgManager = errors.New("integrity: no supported package manager (rpm, dpkg) found")
```

**Test focus per backend:**
- `OwnerOf` parses `rpm -qf <path>` output (one line: package NEVR) and `dpkg -S <path>` output (`pkg: /path` format).
- `Verify` parses `rpm -V <pkg>` output (per-line flags: `S.5....T. /usr/bin/su` → SizeChanged + HashMismatch + MTimeChanged) and `debsums -s <pkg>` output (silent on success; lines starting with `debsums: changed file ...` on mismatch).
- All subprocess calls go through `FakeRunner`; no real `rpm`/`dpkg` invocations in unit tests.
- Integration tests under `//go:build integration` exercise real `rpm`/`dpkg` if present (skip otherwise).

**Acceptance:** one canonical `VerifyResult` shape across both backends; backend-specific `RawOutput` preserved verbatim for evidence.

- [ ] Step 1-5: TDD cycle (one commit per file: `feat(integrity): add PkgMgr interface + Detect`, `feat(integrity): add rpm backend`, `feat(integrity): add dpkg backend`)

#### Task 2.6: internal/procscan — AF_ALG family detection via /proc/<pid>/maps 🚀 RELEASE BLOCKER

**Files:** `internal/procscan/afalg.go`, `internal/procscan/afalg_test.go`, `internal/procscan/modules.go`

**Skill:** `cc-skills-golang:golang-safety` (defensive `/proc` reading; processes can vanish mid-scan)

**Public surface:**
```go
type Candidate struct {
    PID         int
    Comm        string
    MatchReason string // "algif_aead in /proc/1817/maps"
}

type ScanResult struct {
    ScannedPIDs     int
    UnreadablePIDs  []int
    Candidates      []Candidate
}

// Scan walks /proc/[0-9]*/, reads each /proc/<pid>/maps, and flags
// processes whose maps contains any AF_ALG-family module name from
// AFAlgModules. Requires EUID 0; callers should check first and Skip if not.
func Scan(ctx context.Context) (ScanResult, error)

// AFAlgModules is the list of kernel module names whose presence in a
// process's memory map indicates AF_ALG-family socket usage.
var AFAlgModules = []string{"af_alg", "algif_aead", "algif_skcipher", "algif_hash", "algif_rng"}
```

**Test focus:**
- Inject a fake `/proc` filesystem via a `procRoot string` parameter on an unexported helper (not exported on `Scan` — production always uses `/proc`); tests call the helper directly.
- Fixture filesystem: `testdata/procfs-clean/` (no algif), `testdata/procfs-with-encfs/` (one process with `algif_aead`).
- Verify processes that vanish mid-scan (ENOENT on second open) are silently skipped.
- Verify processes that return EACCES are recorded in `UnreadablePIDs`.
- Honor `ctx.Done()` between PID iterations.

**Acceptance:** Scan against the clean fixture returns zero candidates; against the with-encfs fixture returns exactly one candidate with the expected `MatchReason`.

- [ ] Step 1-5: TDD cycle, commit `feat(procscan): add AF_ALG family detection via /proc/<pid>/maps`

#### Task 2.7: internal/hostinfo — /etc/os-release + uname + hostname

**Files:** `internal/hostinfo/hostinfo.go`, `internal/hostinfo/hostinfo_test.go`, `internal/hostinfo/osrelease_fuzz_test.go`

**Public surface:**
```go
func Gather(ctx context.Context, runner exec.Runner) (report.HostInfo, error)
func ParseOSRelease(r io.Reader) (id, versionID, prettyName string, err error)
```

**Test focus:**
- `ParseOSRelease` against samples from AL2/AL2023/Ubuntu 22.04/Rocky 9 in `testdata/`.
- Quoted vs unquoted values both handled (`ID=ubuntu` and `ID="ubuntu"`).
- `Gather` calls `runner.Run` for `uname -r` and `uname -m`; reads `/etc/os-release` directly.
- Fuzz: `FuzzParseOSRelease` seeded with each testdata file + `""` + binary garbage.

**Acceptance:** Gather returns a populated `report.HostInfo` against any of the four real os-release samples.

- [ ] Step 1-5: TDD cycle, commit `feat(hostinfo): add Gather + os-release parser`

#### Task 2.8: internal/logging — slog construction

**Files:** `internal/logging/logging.go`, `internal/logging/logging_test.go`

**Skill:** `cc-skills-golang:golang-observability` (slog patterns)

**Public surface:**
```go
type Options struct {
    Verbosity int       // 0=warn, 1=info, ≥2=debug
    Writer    io.Writer // default os.Stderr
    RunID     string    // injected as base attribute; default uuid.NewString()
}
func New(opts Options) *slog.Logger
```

**Test focus:**
- Capture log output to a `bytes.Buffer`, parse as JSON, verify expected attributes (`tool`, `version`, `run_id`).
- Verify verbosity 0 suppresses Info; verbosity 1 includes Info but not Debug; verbosity 2 includes Debug + AddSource.
- Verify the default RunID is non-empty (use `crypto/rand`-based ID generator; **avoid** introducing a uuid dependency just for this — a 16-byte hex string is sufficient).

**Acceptance:** structured JSON to stderr; one log line per slog.Logger.X() call.

- [ ] Step 1-5: TDD cycle, commit `feat(logging): add slog factory with verbosity levels and run_id`

#### Task 2.9: Verify Phase 2 acceptance

- [ ] Run `make lint test` — exit 0.
- [ ] Verify `internal/exec.allowedCommands` contains exactly the 8 entries from spec §7 (no `lsof`).
- [ ] Verify `grep -r 'os/exec' internal/ check/ preset/ cmd/` shows imports ONLY in `internal/exec/*.go`.
- [ ] Verify `grep -r 'sh -c\|/bin/sh\|exec.Command(.*sh.*-c' .` returns nothing.

---

## Chunk 3: Behavior + Renderers (Phases 3–4)

### Phase 3 — Check Behavior

Goal: implement `check.Check` interface, `check.Runner` with bounded-parallel execution, panic recovery, and deterministic result ordering. After Phase 3, individual checks (Phase 5) have a stable contract to implement.

#### Task 3.1: check/doc.go — package documentation 🚀 RELEASE BLOCKER

**Files:** `check/doc.go`

**Content:** Package-level godoc explaining the layering rule (imports `report`; never imported by `report`), the `Check.Run` no-mutation contract, and pointing at the spec.

- [ ] Single-step: write doc.go, commit `feat(check): add package documentation`.

#### Task 3.2: check/check.go — Check interface 🚀 RELEASE BLOCKER

**Files:** `check/check.go`, `check/check_test.go`

**Public surface:**
```go
type Check interface {
    ID() string
    Title() string
    Description() string
    Severity() report.Severity
    Applicable(ctx context.Context) (ok bool, reason string)
    Run(ctx context.Context) report.Result
}
```

**Test focus:**
- A nominal `mockCheck` (in test file only, not exported) implementing the interface.
- Verify nothing in the package modifies the host (compile-time check: package imports nothing from `internal/exec`, `os/exec`, or `os` write functions).

- [ ] Step 1-5: TDD cycle, commit `feat(check): add Check interface`

#### Task 3.3: check/runner.go — bounded-parallel Runner 🚀 RELEASE BLOCKER

**Files:** `check/runner.go`, `check/runner_test.go`

**Skill:** `cc-skills-golang:golang-concurrency` (worker pool, `errgroup` or hand-rolled with `sync.WaitGroup`+semaphore)

**Public surface:**
```go
type Runner struct {
    Concurrency int           // 0 = runtime.NumCPU()
    Timeout     time.Duration // 0 = 30s
    Logger      *slog.Logger  // nil = slog.Default()
}
func (r *Runner) Run(ctx context.Context, checks []Check) report.Report
```

**Behavior contract:**
- Bounded worker pool (semaphore-based; do NOT spawn one goroutine per check unboundedly).
- Each check gets `context.WithTimeout(ctx, r.Timeout)`.
- Panic in a check → recover, mark `StateError`, log stack trace at slog ERROR, continue.
- Results assembled in input-slice order (deterministic; collect into pre-allocated slice indexed by position).
- `Applicable(ctx)` is called BEFORE `Run(ctx)`; if `ok==false`, produce a `StateSkip` result with `Detail = reason` and skip `Run`.

**Test focus:**
- 5 checks, concurrency=1, verify they run serially in input order.
- 100 checks, concurrency=10, verify max-in-flight is 10 (using a `sync/atomic` counter inside a mock check).
- One check panics → others still complete; panicking check has `StateError` with `Err` containing "panic:".
- Parent ctx cancelled mid-run → in-flight checks return `StateError` with `Err` containing "context canceled".
- Output `Report.Results` order matches input `checks` order regardless of completion order.

- [ ] Step 1-5: TDD cycle, commit `feat(check): add bounded-parallel Runner with panic recovery`

#### Task 3.4: check/runner_concurrency_test.go — race + cancellation tests

**Files:** `check/runner_concurrency_test.go`

**Test focus:**
- Long-running check ignores ctx; runner timeout still kills it after `Runner.Timeout`.
- 1000 checks, concurrency=4, no race detector warnings.
- Goroutine leak check: capture `runtime.NumGoroutine()` before/after Run; allow ±2 for runtime variance.

- [ ] Step 1-5: TDD cycle, commit `test(check): add concurrency, leak, and cancellation tests`

---

### Phase 4 — Renderers

Goal: implement the four output formats. All four register themselves with `report.Register` from `internal/render/init.go`. After Phase 4, `report.Report.WriteTo(w, format)` produces the right bytes for any of `human`, `json`, `sarif`, `prometheus`.

**Parallelizable:** Tasks 4.1–4.4 are independent; can be implemented in any order or in parallel.

#### Task 4.1: internal/render/init.go + render.go — registration 🚀 RELEASE BLOCKER

**Files:** `internal/render/init.go`, `internal/render/render.go`

**Public surface:** None (all exported entry points live on `report.Report.WriteTo`). The init function registers every renderer:
```go
func init() {
    report.Register(report.FormatHuman, RenderHuman)
    report.Register(report.FormatJSON, RenderJSON)
    report.Register(report.FormatSARIF, RenderSARIF)
    report.Register(report.FormatPrometheus, RenderPrometheus)
}
```

**Critical: blank-import contract.** Because `internal/render` registers renderers via package-level `init()` and is otherwise unreferenced by `cmd/copyfail-validate/main.go`, the CLI MUST blank-import it:
```go
import _ "github.com/polyglotdev/copyfail-validation/internal/render" // register renderers
```
If this import is removed (e.g., by an over-eager `goimports` cleanup), `report.Report.WriteTo` will return `ErrRendererNotRegistered` for every format and the CLI will silently break at runtime. Defenses against accidental removal:

1. The `package render` doc comment at the top of `internal/render/render.go` MUST state explicitly: "Consumers (the CLI, tests) must blank-import this package; otherwise no renderer is registered and report.Report.WriteTo returns ErrRendererNotRegistered."
2. `cmd/copyfail-validate/main.go` keeps a `// register renderers — DO NOT REMOVE; see internal/render/render.go` comment on the blank import line.
3. The CLI integration test in Task 6.2 (`TestCLI_JSONFormat_IsParseable`) is the regression test — it would fail loudly if renderers stopped registering.

**Test focus:** Importing `internal/render` (e.g., from `cmd/copyfail-validate/main.go`) registers all four; calling `rep.WriteTo(w, FormatJSON)` no longer returns `ErrRendererNotRegistered`. Add a unit test in `internal/render/render_test.go` that imports its own package via blank-import and verifies all four formats are registered.

- [ ] Step 1: Write failing test that imports `internal/render` and asserts all four formats are registered (use `report.Register`-introspection-helper if needed; otherwise call `report.Report{}.WriteTo(io.Discard, f)` for each format and assert no `ErrRendererNotRegistered`).
- [ ] Step 2: Implement `init.go` and `render.go` with the package doc comment requirement above.
- [ ] Step 3: Verify pass.
- [ ] Step 4: Verify the package doc string in `render.go` mentions the blank-import requirement.
- [ ] Step 5: Commit `feat(render): wire renderer registration via init + document blank-import contract`

#### Task 4.2: internal/render/json.go 🚀 RELEASE BLOCKER

**Files:** `internal/render/json.go`, `internal/render/json_test.go`

**Behavior:**
- Pretty-print with `json.Indent` (two-space indent) by default (operators read it).
- Override via env `COPYFAIL_JSON_COMPACT=1` to emit single-line output (smaller for log shipping).
- Trailing newline.

**Test focus:**
- Round-trip: `WriteTo(buf, FormatJSON)` then `json.Unmarshal(buf.Bytes(), &report.Report{})` reproduces the original.
- Stable byte-identical output across runs given the same input.
- `cmp.Diff` against a golden file in `testdata/golden/json/basic.json`.

- [ ] Step 1-5: TDD cycle, commit `feat(render): add JSON renderer`

#### Task 4.3: internal/render/human.go 🚀 RELEASE BLOCKER

**Files:** `internal/render/human.go`, `internal/render/human_test.go`, `internal/render/testdata/golden/human/*.txt`

**Behavior:**
- ANSI colors honored only when `term.IsTerminal(int(os.Stdout.Fd()))` AND `NO_COLOR` env is unset.
- Per-result line: `STATUS  check.id (severity): detail` with status as `OK`/`FAIL`/`SKIP`/`ERROR`.
- Footer: `validator result: PASS|FAIL` + tally.

**Test focus:**
- Golden-file test with ANSI off (deterministic).
- Verify `NO_COLOR=1` produces plain output even on a TTY.
- `-update` flag regenerates golden files.

- [ ] Step 1-5: TDD cycle, commit `feat(render): add human renderer with ANSI + NO_COLOR support`

#### Task 4.4: internal/render/sarif.go

**Files:** `internal/render/sarif.go`, `internal/render/sarif_test.go`, `internal/render/testdata/golden/sarif/basic.sarif`

**Behavior:** Emit a SARIF v2.1.0 document. One `run` per Report; one `result` per `report.Result`. `result.kind` = `State.SARIFKind()`. `rule.id` = `CheckID`. `rule.shortDescription` = `Title`. `rule.fullDescription` = `Description`.

**Test focus:**
- Validate output against the SARIF JSON schema (commit `testdata/sarif-schema-2.1.0.json` from the OASIS spec; load and validate at test time using a tiny JSON-schema validator; if introducing a dep here is unwanted, instead pin a small set of structural assertions).
- Round-trip via `json.Unmarshal` confirms valid JSON.

- [ ] Step 1-5: TDD cycle, commit `feat(render): add SARIF v2.1.0 renderer`

#### Task 4.5: internal/render/prom.go + atomic textfile write

**Files:** `internal/render/prom.go`, `internal/render/prom_test.go`

**Skill:** `cc-skills-golang:golang-observability` (Prometheus exposition format details)

**Behavior:**
- Emit the metric set from spec §8.2 (`copyfail_validator_check_state` one-hot, `copyfail_validator_check_duration_seconds`, `copyfail_validator_summary`, `copyfail_validator_required_failures`, `copyfail_validator_last_run_timestamp_seconds`, `copyfail_validator_build_info`).
- Use `github.com/prometheus/common/expfmt` for parsing in tests; for emitting, hand-write since the format is simple enough.
- Provide an `WriteTextfileAtomic(dir, baseName string, rep report.Report) error` helper that writes to `dir/baseName.tmp.<rand>` then `os.Rename` to `dir/baseName.prom`.

**Test focus:**
- Output parses cleanly with `expfmt.TextParser{}`.
- Atomic write: SIGKILL-style abort mid-write leaves no `.prom` file (only the `.tmp.<rand>`).
- Concurrent writes from two processes don't produce a half-written file (file-system-level guarantee from `os.Rename` on the same fs).

- [ ] Step 1-5: TDD cycle, commit `feat(render): add Prometheus textfile renderer with atomic write`

---

## Chunk 4: Preset + CLI (Phases 5–6)

### Phase 5 — preset/copyfail Checks

Goal: implement each of the 9 day-one checks from spec §11 as a separate file in `preset/copyfail/`. Each check is its own Go type implementing `check.Check`. After Phase 5, `copyfail.All()` returns the full bundle and a test against a real Linux box (or fixture) produces a meaningful report.

**Pattern shared across all preset tasks:**

```go
// Each check follows this skeleton:
type kernelVersionCheck struct {
    runner exec.Runner
}

func (kernelVersionCheck) ID() string                  { return "kernel.version" }
func (kernelVersionCheck) Title() string               { return "Kernel release" }
func (kernelVersionCheck) Description() string         { return "Records the running kernel release as host context." }
func (kernelVersionCheck) Severity() report.Severity   { return report.SeverityAdvisory }
func (kernelVersionCheck) Applicable(context.Context) (bool, string) { return true, "" }
func (c kernelVersionCheck) Run(ctx context.Context) report.Result { ... }
```

**Each task contributes one file pair (`<check_id>.go` + `<check_id>_test.go`) and uses the FakeRunner pattern from Phase 2.**

#### Task 5.1: preset/copyfail/doc.go + copyfail.go (CVE const + All bundler) 🚀 RELEASE BLOCKER

**Files:** `preset/copyfail/doc.go`, `preset/copyfail/copyfail.go`, `preset/copyfail/copyfail_test.go`

**Public surface:**
```go
const CVE = "CVE-2026-31431"

// Options configures the copyfail check bundle. Zero value uses defaults.
type Options struct {
    Module   string       // default "algif_aead"
    ConfPath string       // default "/etc/modprobe.d/disable-algif-aead.conf"
    Runner   exec.Runner  // default exec.NewOSRunner()
}

// All returns the full check bundle.
func All() []check.Check
func AllWithOptions(opts Options) []check.Check
```

**Test focus:** `All()` returns 9 checks (the catalog from spec §11); each check ID is unique.

- [ ] Step 1-5: TDD cycle, commit `feat(copyfail): add Options + All()/AllWithOptions bundle`

#### Tasks 5.2–5.10: One per check (advisory or required per spec §11) 🚀 RELEASE BLOCKER (5.4-5.8 only)

Each task follows the same pattern. Files and commit messages:

| Task | Check ID | Files | RELEASE BLOCKER? |
|---|---|---|---|
| 5.2 | `kernel.version` | `kernel_version.go` + test | No (advisory) |
| 5.3 | `hostinfo.os_release` | `hostinfo_os_release.go` + test | No (advisory) |
| 5.4 | `modprobe.conf_present` | `modprobe_conf_present.go` + test | 🚀 |
| 5.5 | `modprobe.conf_correct` | `modprobe_conf_correct.go` + test | 🚀 |
| 5.6 | `modprobe.dry_run` | `modprobe_dry_run.go` + test | 🚀 |
| 5.7 | `modprobe.dependency_chain` | `modprobe_dependency_chain.go` + test | 🚀 |
| 5.8 | `module.not_loaded` | `module_not_loaded.go` + test | 🚀 |
| 5.9 | `afalg.no_active_users` | `afalg_no_active_users.go` + test | No (advisory) |
| 5.10 | `integrity.su_binary` | `integrity_su_binary.go` + test | No (advisory) |

For each task:

- [ ] Step 1: Write failing test using `FakeRunner` to feed canned subprocess output for the pass/fail/skip/error scenarios from spec §11.
- [ ] Step 2: Implement the check struct + methods, delegating actual subprocess work to `internal/kernelmod`, `internal/integrity`, or `internal/procscan`.
- [ ] Step 3: Verify Run produces the right `report.Result` for each scenario (Pass, Fail, Skip with reason, Error with cause).
- [ ] Step 4: Add to `All()` in copyfail.go.
- [ ] Step 5: Commit `feat(copyfail): add <check_id> check`.

#### Task 5.11: preset/copyfail end-to-end smoke test against the host

**Files:** `preset/copyfail/copyfail_smoke_test.go` (build tag `integration`)

**Test focus:**
- `All()` against the real host (whichever Linux distro the test runs on — likely Ubuntu in GitHub Actions).
- Assert the report has the expected number of results.
- Assert there are no `StateError` results (a Skip is fine).
- Run only with `go test -tags=integration`.

- [ ] Step 1-5: TDD cycle, commit `test(copyfail): add integration smoke test`

#### Task 5.12: Delete the legacy copyfail_validator.go (deferred — see Phase 6)

> **ORDERING NOTE (corrected per plan-reviewer iteration 1):** This task is intentionally **deferred to AFTER Task 6.3 (`go install` verification) passes**. Deleting the legacy prototype before verifying that the new CLI works end-to-end leaves no fallback if 6.3 fails. The original Task 5.12 in this slot has moved to **Task 6.4** below; this entry is left in place as a tombstone so the numbering of subsequent tasks doesn't shift.

- [ ] (No-op) — see Task 6.4.

---

### Phase 6 — CLI

Goal: ship `cmd/copyfail-validate` as a thin frontend over the library. After Phase 6, `go install github.com/polyglotdev/copyfail-validation/cmd/copyfail-validate@HEAD` works end-to-end.

#### Task 6.1: cmd/copyfail-validate/main.go + flags.go + exit.go 🚀 RELEASE BLOCKER

**Files:**
- `cmd/copyfail-validate/main.go` — entry point (~30 LOC)
- `cmd/copyfail-validate/flags.go` — flag parsing (`flag` package; do NOT introduce cobra/urfave for v0.1 — YAGNI)
- `cmd/copyfail-validate/exit.go` — exit-code computation per spec §6
- `cmd/copyfail-validate/flags_test.go`
- `cmd/copyfail-validate/exit_test.go`

**main.go (full content; small enough to inline):**

```go
// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Command copyfail-validate is the CLI frontend for the copyfail-validation library.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/polyglotdev/copyfail-validation/check"
	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/internal/hostinfo"
	"github.com/polyglotdev/copyfail-validation/internal/logging"
	_ "github.com/polyglotdev/copyfail-validation/internal/render" // register renderers
	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
	"github.com/polyglotdev/copyfail-validation/report"
)

func main() {
	opts, err := parseFlags(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitUsage)
	}
	os.Exit(run(opts))
}

func run(opts options) int {
	logger := logging.New(logging.Options{Verbosity: opts.Verbose, Writer: os.Stderr})
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	runner := exec.NewOSRunner()
	host, err := hostinfo.Gather(ctx, runner)
	if err != nil {
		logger.Error("hostinfo gather failed", "err", err)
		return exitToolError
	}

	checks := copyfail.AllWithOptions(copyfail.Options{
		Module: opts.Module, ConfPath: opts.Conf, Runner: runner,
	})
	checks = filter(checks, opts.Only, opts.Skip)

	r := check.Runner{
		Concurrency: opts.Concurrency,
		Timeout:     opts.Timeout,
		Logger:      logger,
	}
	rep := r.Run(ctx, checks)
	rep.SchemaVersion = report.SchemaVersionCurrent
	rep.Tool = buildinfo.Info()
	rep.Host = host
	rep.Generated = nowFunc()

	output, closer, err := openOutput(opts.Output)
	if err != nil {
		logger.Error("open output", "err", err)
		return exitToolError
	}
	defer closer()
	if _, err := rep.WriteTo(output, opts.Format); err != nil {
		logger.Error("render", "err", err)
		return exitToolError
	}
	return computeExit(ctx, rep)
}

// nowFunc is overridable in tests for stable Generated timestamps.
var nowFunc = func() time.Time { return time.Now().UTC() }
```

**flags.go:** parse `--format`, `--output`, `--timeout`, `--concurrency`, `--module`, `--conf`, `--skip`, `--only`, `--sign`, `--no-color`, `-v`/`-vv`, `--version`, `--help`. Return an `options` struct + error (usage error → caller exits 64). Default format = `human` if `term.IsTerminal(int(os.Stdout.Fd()))`, else `json`. Honor `COPYFAIL_FORMAT`/`COPYFAIL_TIMEOUT`/`COPYFAIL_MODULE`/`COPYFAIL_CONF` env as fallback.

**exit.go:** Implement the priority order from spec §6:
```go
const (
	exitOK            = 0
	exitMitigationGap = 2
	exitToolError     = 3
	exitCheckError    = 4
	exitUsage         = 64
)
func computeExit(ctx context.Context, rep report.Report) int { ... }
```

- [ ] Step 1: Write failing tests for `parseFlags` (table-driven with every flag combination).
- [ ] Step 2: Write failing tests for `computeExit` (one per row of the spec §6 exit-code table).
- [ ] Step 3: Implement.
- [ ] Step 4: Verify all pass.
- [ ] Step 5: Commit `feat(cli): add main, flags, exit-code computation`

#### Task 6.2: cmd/copyfail-validate/main_test.go — CLI integration tests 🚀 RELEASE BLOCKER

**Files:** `cmd/copyfail-validate/main_test.go`

**Pattern:**
```go
func TestMain(m *testing.M) {
    // Build the binary once into t.TempDir-equivalent path; cache via sync.Once.
    // ...
    os.Exit(m.Run())
}
func TestCLI_JSONFormat_IsParseable(t *testing.T) { ... }
func TestCLI_HumanFormat_NoColor(t *testing.T) { ... }
func TestCLI_VersionFlag(t *testing.T) { ... }
func TestCLI_HelpFlag(t *testing.T) { ... }
func TestCLI_UnknownFlag_ExitsWithUsage(t *testing.T) { ... }
func TestCLI_OnlyOneCheck(t *testing.T) { ... }
func TestCLI_SkipPattern(t *testing.T) { ... }
func TestCLI_SIGTERM_Exits143_PartialReportValid(t *testing.T) { ... }
```

- [ ] Step 1-5: TDD cycle, commit `test(cli): add CLI integration tests`

#### Task 6.3: Verify `go install` works end-to-end 🚀 RELEASE BLOCKER

- [ ] Step 1: `go install github.com/polyglotdev/copyfail-validation/cmd/copyfail-validate@HEAD` (using the local module cache; effectively `go install ./cmd/copyfail-validate`).
- [ ] Step 2: `which copyfail-validate && copyfail-validate --version` produces `v0.0.0-dev` (the buildinfo default).
- [ ] Step 3: `copyfail-validate --format=json --only=hostinfo.os_release` returns a one-result JSON report on Linux; on macOS the check returns Skip and exit code 0.
- [ ] Step 4: `copyfail-validate --format=json` (full bundle) on the dev host produces a complete, parseable JSON report; if any required check returns Error or Fail, investigate before deleting the legacy file in 6.4.
- [ ] Step 5: No commit (verification only).

#### Task 6.4: Delete the legacy copyfail_validator.go.legacy 🚀 RELEASE BLOCKER

> **PRECONDITION:** Task 6.3 must have passed completely. If 6.3 reported any required-check Fail or any Error, do NOT proceed — fix the implementation first. The legacy prototype is the rollback path.

> **NAME NOTE:** The file was renamed early in Phase 1 from `copyfail_validator.go` to `copyfail_validator.go.legacy` to silence IDE diagnostics (the `.go.legacy` extension is not parsed as Go). Reference content is unchanged.

**Files (delete):** `copyfail_validator.go.legacy`

**Acceptance:** `ls copyfail_validator.go*` returns empty after the rm.

- [ ] Step 1: Re-confirm 6.3 passed (re-run if more than a few hours have elapsed or any new commits have landed).
- [ ] Step 2: Compare-output sanity check: temporarily rename `copyfail_validator.go.legacy` back to `.go`, run `go run copyfail_validator.go` and the new CLI (`./dist/copyfail-validate`) side-by-side on the dev host; verify the new CLI's results are a strict superset of the legacy output (extra checks: `modprobe.dependency_chain`, `hostinfo.os_release`); rename back to `.legacy` after.
- [ ] Step 3: `rm copyfail_validator.go.legacy` (file was never tracked in git, so `git rm` is not appropriate; just `rm`).
- [ ] Step 4: Commit `refactor: remove legacy copyfail_validator.go monolith

The new preset/copyfail bundle (9 checks) covers everything the legacy
script did plus modprobe.dependency_chain and hostinfo.os_release. See
preset/copyfail/All() and docs/checks.md for the migration map.

Only deleted after Task 6.3 verified the new CLI installs and runs
end-to-end on the dev host."

---

## Chunk 5: Distribution + Release (Phases 7–8)

### Phase 7 — Distribution Scaffolding

Goal: every artifact pkg.go.dev needs, every CI workflow, every supply-chain control. After Phase 7, the repo is one `git tag v0.1.0 && git push --tags` away from a green release.

**All Phase 7 tasks are parallelizable** — they touch disjoint files.

#### Task 7.1: SPDX license headers in every .go file 🚀 RELEASE BLOCKER

- [ ] Step 1: Write a small script `scripts/add-license-headers.sh` that prepends the two-line SPDX header to any `.go` file lacking it.
- [ ] Step 2: Run it; manually verify the diff.
- [ ] Step 3: Commit `chore: add SPDX license headers to all Go files`.
- [ ] Step 4: Add a CI lint that fails the build if any `.go` file is missing the header (small check in `.github/workflows/test.yml`).

#### Task 7.2: SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, RELEASING.md 🚀 RELEASE BLOCKER (SECURITY.md only)

- [ ] Step 1: Write each file from the spec §10 deliverables list.
- [ ] Step 2: Commit `docs: add SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, RELEASING`.

#### Task 7.3: docs/checks.md — catalog of every check 🚀 RELEASE BLOCKER

- [ ] Step 1: For each of the 9 checks in `preset/copyfail`, write a section with: ID, title, severity, applicability, Pass/Fail/Skip/Error semantics, Evidence shape, SARIF rule ID.
- [ ] Step 2: Commit `docs: add check catalog`.

#### Task 7.4: docs/schema.md + schemas/report-1.0.0.json

- [ ] Step 1: Write `docs/schema.md` from spec §5.
- [ ] Step 2: Write a JSON Schema (Draft 2020-12) describing `report.Report`. Validate it against an emitted sample report in CI.
- [ ] Step 3: Commit `docs: add schema documentation + JSON Schema for v1.0.0`.

#### Task 7.5: docs/runbook-ssm.md + docs/runbook-prometheus.md

- [ ] Step 1: SSM runbook: copy-paste SSM Document examples for AL2/AL2023/Ubuntu 22.04, including how to ship results to S3/CloudWatch.
- [ ] Step 2: Prometheus runbook: cron + textfile collector + alerting rule.
- [ ] Step 3: Commit `docs: add SSM and Prometheus runbooks`.

#### Task 7.6: examples/basic/main.go

- [ ] Step 1: Write a 30-line example showing library usage (call `copyfail.All()`, run the `check.Runner`, print as JSON).
- [ ] Step 2: Add a `func ExampleAll()` test in `preset/copyfail/example_test.go` so it appears on pkg.go.dev.
- [ ] Step 3: Commit `docs: add basic example for library consumers`.

#### Task 7.7: .goreleaser.yaml 🚀 RELEASE BLOCKER

- [ ] Step 1: Write `.goreleaser.yaml` per spec §10. Include builds (linux/amd64, linux/arm64), archives, checksums + cosign keyless signing, SBOMs (syft), nfpm packages (deb/rpm/apk), GHCR docker image, GitHub Release.
- [ ] Step 2: Verify locally: `goreleaser release --snapshot --clean` succeeds.
- [ ] Step 3: Commit `build: add goreleaser config`.

#### Task 7.8: Dockerfile.release

- [ ] Step 1: Distroless multi-stage build using `gcr.io/distroless/static:nonroot` for the runtime stage. The binary runs as nonroot user, reads-only.
- [ ] Step 2: Verify: `docker build -f Dockerfile.release -t copyfail-validate:test . && docker run --rm copyfail-validate:test --version`.
- [ ] Step 3: Commit `build: add distroless Dockerfile for release image`.

#### Task 7.9: .github/workflows/test.yml 🚀 RELEASE BLOCKER

- [ ] Step 1: Workflow runs on push + PR: matrix Go (1.26.x, stable) × OS (ubuntu-22.04, ubuntu-24.04). Steps: setup-go, restore go cache, `make lint`, `make test`, `make vuln`, upload coverage to codecov.
- [ ] Step 2: Add a job that fails if any `.go` file lacks the SPDX header (one-line grep).
- [ ] Step 3: Commit `ci: add test workflow`.

#### Task 7.10: .github/workflows/release.yml 🚀 RELEASE BLOCKER

- [ ] Step 1: Workflow triggers on tag `v*`. Calls GoReleaser; calls `slsa-github-generator` for SLSA L3 provenance.
- [ ] Step 2: Commit `ci: add release workflow with SLSA L3 provenance`.

#### Task 7.11: .github/workflows/scorecard.yml + codeql.yml + dependabot.yml

- [ ] Step 1: Each workflow per the standard OSSF / GitHub templates.
- [ ] Step 2: Commit `ci: add OpenSSF Scorecard, CodeQL, and Dependabot`.

#### Task 7.12: README.md full rewrite 🚀 RELEASE BLOCKER

- [ ] Step 1: Replace the skeleton with the full README per spec §10. Include: badges (pkg.go.dev, Go Reference, License, OpenSSF Scorecard, SLSA L3), one-paragraph what/why, quick-start (`go install`), architecture diagram (ASCII from spec §3), runnable example, runbook links, security policy link, contributor guide link, license.
- [ ] Step 2: Commit `docs: full README for v0.1.0`.

#### Task 7.13: Module-level doc.go 🚀 RELEASE BLOCKER

**Why blocker:** pkg.go.dev surfaces the module's top-level package doc as the landing page summary. Shipping v0.1.0 without this leaves the most-visible piece of documentation blank.

- [ ] Step 1: Write `/Users/domhallan/projects/personal/copyfail-validation/doc.go` (module-level package doc; appears as the pkg.go.dev landing page summary). Cover: what the module is, the three public packages and their roles, the link to the spec, the link to docs/checks.md, the SSM-quickstart one-liner.
- [ ] Step 2: Verify `go doc github.com/polyglotdev/copyfail-validation` (run from outside the module) renders the new doc.
- [ ] Step 3: Commit `docs: add module-level package doc for pkg.go.dev landing`.

---

### Phase 8 — Release v0.1.0

Goal: tag v0.1.0, verify the release pipeline produces all expected artifacts, verify pkg.go.dev picks up the module.

#### Task 8.1: e2e Dockerfiles

- [ ] Step 1: `e2e/al2023/Dockerfile` — Amazon Linux 2023 with mitigation correctly applied.
- [ ] Step 2: `e2e/ubuntu2204/Dockerfile` — Ubuntu 22.04 unmitigated (bare).
- [ ] Step 3: `e2e/rocky9-drift/Dockerfile` — Rocky 9 with conf present but module also loaded (drift scenario).
- [ ] Step 4: `e2e/run.sh` — builds the binary, mounts it into each container, runs it, asserts on exit code.
- [ ] Step 5: Commit `test(e2e): add per-distro Dockerfiles + run.sh`.

#### Task 8.2: Final pre-release checklist 🚀 RELEASE BLOCKER

Run through the spec §10 initial-release checklist:

- [ ] All public symbols have godoc (verified by `golangci-lint run` with `revive.exported`).
- [ ] At least one `Example_*` test per public package.
- [ ] `LICENSE`, `README.md`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md` present.
- [ ] CI green on main.
- [ ] `go mod tidy && git diff --exit-code go.mod go.sum` exits 0 (no untracked module dirtiness; if it fails, investigate before tagging — a dirty go.sum at tag time means the proxy may serve a different sum than what was tested).
- [ ] `goreleaser release --snapshot --clean` succeeds locally.
- [ ] `go install github.com/polyglotdev/copyfail-validation/cmd/copyfail-validate@HEAD` works on a clean GOPATH.
- [ ] Manual run on one AL2023 container, one Ubuntu 22.04 container, and one Rocky 9 drift scenario; outputs match expected.
- [ ] CHANGELOG `[Unreleased]` section moved under `## [0.1.0] - 2026-MM-DD` (the date is whatever the actual tag date is).
- [ ] All commits since the spec are signed (verify via `git log --show-signature` — every commit shows `gpg: Good signature`).
- [ ] `git status` clean (no uncommitted work) and current branch is `main` (not a feature branch).

#### Task 8.3: Tag v0.1.0 🚀 RELEASE BLOCKER (terminal step)

- [ ] Step 1: `git tag -s v0.1.0 -m "v0.1.0: initial public release"` (signed tag).
- [ ] Step 2: `git push origin main && git push origin v0.1.0`.
- [ ] Step 3: Wait for `release.yml` to complete; verify GitHub Release has all expected artifacts (binaries × 2 archs, checksums.txt, .sig, SBOMs, .deb, .rpm, .apk, container manifest).
- [ ] Step 4: Trigger pkg.go.dev to crawl: `curl -fsSL "https://proxy.golang.org/github.com/polyglotdev/copyfail-validation/@v/v0.1.0.info"` (the proxy fetches on first request).
- [ ] Step 5: Verify <https://pkg.go.dev/github.com/polyglotdev/copyfail-validation> shows the package within ~10 minutes.
- [ ] Step 6: Final commit (post-release): `chore: bump CHANGELOG to next [Unreleased]`.

---

## Critical-Path Summary

The minimum sequence to ship v0.1.0 (corrected per plan-reviewer iteration 1):

```
0.1 → 0.2 → 0.3 → 0.5 → 0.6
  → 1.1 → 1.2 → 1.3 → 1.4 → 1.5 → 1.6 → 1.7 → 1.8                                   (1.8 = redact, security-required)
  → 2.1 (a, b, c) → 2.2 → 2.3 → 2.5 → 2.6
  → 3.1 → 3.2 → 3.3
  → 4.1 → 4.2 → 4.3                                                                  (4.1 first — registers renderers)
  → 5.1 → 5.4 → 5.5 → 5.6 → 5.7 → 5.8
  → 6.1 → 6.2 → 6.3 → 6.4                                                            (6.4 = legacy delete; was 5.12, moved AFTER 6.3)
  → 7.1 → 7.2 (SECURITY.md only) → 7.3 → 7.7 → 7.9 → 7.10 → 7.12 → 7.13              (7.13 = module-level doc.go for pkg.go.dev)
  → 8.2 → 8.3
```

Everything NOT on the critical path can ship in a v0.1.x patch:

- Advisory checks 5.2 (`kernel.version`), 5.3 (`hostinfo.os_release`), 5.9 (`afalg.no_active_users`), 5.10 (`integrity.su_binary`)
- SARIF renderer 4.4
- Prometheus renderer 4.5
- e2e Dockerfiles 8.1
- OpenSSF Scorecard / CodeQL / Dependabot 7.11
- examples/basic/ 7.6
- schema docs + JSON Schema 7.4
- runbooks 7.5

These are valuable but not blockers — shipping v0.1.0 with the critical-path set produces a working `copyfail-validate` CLI that emits human + JSON output and exits with the spec's exit codes; everything else is additive.

### What changed vs the first draft of this section

| Was | Is | Why |
|---|---|---|
| 1.4 missing from path | 1.4 added | `report.Format` is referenced by both 1.7 and 6.1 — the build doesn't compile without it |
| 1.8 missing from path | 1.8 added | Spec §7 commits to redaction running on every Evidence/Detail string — security-required for v0.1 |
| 4.1 missing from path | 4.1 added before 4.2 | Without renderer registration via init, `report.WriteTo` returns ErrRendererNotRegistered |
| 5.12 in path before 6.3 | Renamed to 6.4, placed after 6.3 | Deleting the legacy file before verifying `go install` works leaves no rollback |
| 7.13 missing from path | 7.13 added | pkg.go.dev landing page is empty without module-level doc.go |

## Execution Handoff

Plan complete and saved to [`docs/superpowers/plans/2026-05-04-copyfail-validation-v0.1.md`](2026-05-04-copyfail-validation-v0.1.md).

This harness has subagents available. Use **`superpowers:subagent-driven-development`** to execute: dispatch one fresh subagent per task with the spec + this plan + the relevant skill cross-reference loaded. Two-stage review (implementer + verifier) per task.
