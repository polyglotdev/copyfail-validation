// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package render implements the four output renderers (human, JSON,
// SARIF v2.1.0, and Prometheus textfile) that turn a report.Report into
// bytes on a writer. Each renderer is registered with the report package
// at init() time; the report package itself stays a leaf in the
// dependency graph (it owns the registry but knows nothing about any
// concrete format).
//
// # Blank-import contract — DO NOT REMOVE
//
// Consumers (the CLI, tests) MUST blank-import this package; otherwise
// no renderer is registered and report.Report.WriteTo returns
// ErrRendererNotRegistered for every Format. The CLI keeps a comment
// next to the import to deter accidental removal by goimports cleanup:
//
//	import _ "github.com/polyglotdev/copyfail-validation/internal/render"
//
// If the import is dropped, every CLI run silently fails with
// ErrRendererNotRegistered. The CLI integration test
// (cmd/copyfail-validate, Phase 6) is the regression test that catches
// the regression loudly. Prefer that over relying on operator-eye.
//
// # Determinism
//
// Every renderer is deterministic for a given Report value: same input
// bytes yield identical output bytes across runs. Tests in this package
// pin output via golden files (see testdata/golden) and the JSON
// renderer is exercised additionally for round-trip stability.
//
// # Standard library only
//
// The runtime build of this package depends on stdlib only — no
// prometheus/common, no golang.org/x/term, no JSON-schema validators.
// External tooling (cmp/cmp from google/go-cmp) is used only in tests.
// Any new runtime import requires a deliberate revisit of the design
// goal stated in the plan (Phase 4 task 4.5).
package render
