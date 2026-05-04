// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package check defines the Check interface that every validator unit
// implements and the Runner that executes a slice of Checks in a
// bounded worker pool.
//
// # Layering rule
//
// This package is positioned ABOVE the report package and BELOW any
// concrete preset (preset/copyfail/...) and the CLI (cmd/...). The
// non-test source files here import EXACTLY ONE other package from
// this module: report. They do NOT import internal/* (no subprocess,
// no /proc parsing, no integrity backends), they do NOT import any
// preset/* (no concrete checks), and they do NOT import cmd/*.
//
// The rule is enforced at lint time by the depguard configuration in
// .golangci.yml ("check-imports-only-report"). The intent: a downstream
// consumer (or a future second preset) can pull in only the check
// package without dragging in every internal probe and rendering
// helper. The Runner has no knowledge of any specific Check type; it
// just orchestrates the slice it is given.
//
// Tests in this package are exempt from the depguard rule, so test
// files MAY import internal/* helpers (e.g., to drive an integration
// scenario through a real internal/exec runner) when useful.
//
// # Mutation contract
//
// Check implementations MUST be read-only with respect to host state.
// A check that touches /proc, /sys, /etc, /var, modifies environment
// variables, writes to disk outside of a unit-test temp directory, or
// changes any subprocess's behavior is a bug. The Runner does not
// (and cannot) enforce this at runtime; reviewers and integration
// tests catch it instead. The contract is documented on the Check
// interface so implementations have a single canonical reference.
//
// # Concurrency contract
//
// Check implementations MUST be safe to call concurrently with other
// Checks. The Runner runs them in a bounded worker pool by default
// (Runner.Concurrency, defaulting to runtime.NumCPU()). A Check that
// shares state with siblings via package-level variables, global
// caches, or singleton resources is broken — the data race is real
// even if the test suite never observes it.
//
// # References
//
//   - docs/superpowers/specs/2026-05-04-copyfail-validation-design.md
//     §4 (Public API Surface — package check)
//   - docs/superpowers/specs/2026-05-04-copyfail-validation-design.md
//     §5 (Data Flow & Result Lifecycle — concurrency model)
//   - docs/superpowers/specs/2026-05-04-copyfail-validation-design.md
//     §6 (Error Handling — note: the Runner does NOT compute exit
//     codes; the CLI does, from Report.Summary.Required)
package check
