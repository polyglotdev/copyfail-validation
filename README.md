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
