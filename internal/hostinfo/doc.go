// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package hostinfo gathers host identity for the report header
// (report.HostInfo): hostname, kernel release, OS release / version,
// and CPU architecture. The Gather entry point combines a direct
// stdlib syscall (os.Hostname), two safe-allowlist subprocesses
// (`uname -r`, `uname -m`) routed through internal/exec, and a pure
// reader-based parser for /etc/os-release.
//
// # Why this is its own package (and not part of buildinfo)
//
// buildinfo describes the BINARY (version, commit, build date) and
// must remain a tiny, dependency-free leaf so the CLI can import it
// without dragging in any system-state code. hostinfo describes the
// HOST the binary is running against and necessarily depends on
// internal/exec (for uname) and the report wire shape. Splitting them
// keeps buildinfo importable from arbitrary tooling (for instance, a
// future debug-build introspection helper) without inheriting hostinfo's
// /proc and exec dependencies.
//
// # /etc/os-release tolerance contract
//
// The parser is deliberately tolerant. The os-release(5) spec permits
// arbitrary additional content beyond the well-known keys, plus three
// shell-style quoting forms (unquoted, single-quoted, double-quoted)
// per value. A malformed line that does not match the KEY=VALUE shape
// is silently skipped — distributions add custom keys without warning,
// and an audit must not refuse to run because a vendor extended the
// file. Only the (ID, VERSION_ID, PRETTY_NAME) tuple is extracted;
// everything else is ignored.
//
// # Spec reference
//
// See docs/superpowers/specs/2026-05-04-copyfail-validation-design.md
// §11 for the hostinfo.os_release evidence shape.
package hostinfo
