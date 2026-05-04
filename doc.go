// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package copyfailvalidation is the module-level entry point for
// godoc / pkg.go.dev. The actual library API lives in the public
// subpackages:
//
//   - report  — value types (State, Severity, Result, Report, Format,
//     Summary). The leaf of the dependency graph; imports nothing
//     else in this module.
//   - check   — the Check interface and the bounded-parallel Runner.
//   - preset/copyfail — the day-one validator preset for CVE-2026-31431.
//
// Quick start (CLI):
//
//	go install github.com/polyglotdev/copyfail-validation/cmd/copyfail-validate@latest
//	sudo copyfail-validate
//
// Quick start (library):
//
//	import (
//	    "context"
//	    "os"
//	    "github.com/polyglotdev/copyfail-validation/check"
//	    _ "github.com/polyglotdev/copyfail-validation/internal/render"
//	    "github.com/polyglotdev/copyfail-validation/preset/copyfail"
//	    "github.com/polyglotdev/copyfail-validation/report"
//	)
//
//	func main() {
//	    rep := (&check.Runner{}).Run(context.Background(), copyfail.All())
//	    _, _ = rep.WriteTo(os.Stdout, report.FormatJSON)
//	}
//
// See https://github.com/polyglotdev/copyfail-validation for the spec,
// the implementation plan, the check catalog (docs/checks.md), and the
// SSM / Prometheus runbooks.
package copyfailvalidation
