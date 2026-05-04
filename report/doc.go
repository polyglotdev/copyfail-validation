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
