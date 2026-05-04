// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package copyfail provides the validator preset for CVE-2026-31431
// ("copyfail"), an AF_ALG-family Linux kernel-crypto vulnerability.
//
// The package returns a slice of [check.Check] implementations that
// together verify the canonical mitigation posture: the target kernel
// module is blocklisted in /etc/modprobe.d, modprobe -n -v resolves
// the module to /bin/false, no later-sorting modprobe.d file overrides
// the blocklist, and the module is not currently loaded into the
// running kernel.
//
// # Layout
//
// The exported entry points are:
//
//   - [All]              — the default check bundle.
//   - [AllWithOptions]   — same bundle, with caller-supplied [Options].
//   - [Options]          — module name, conf path, modprobe.d directory,
//     and subprocess [exec.Runner] override.
//   - [CVE], [DefaultModule], [DefaultConfPath] — package-level
//     constants documenting the canonical defaults.
//
// Each check is a small struct in its own file; the bundler in
// copyfail.go composes them and applies defaults. The checks delegate
// every probe to packages under internal/* (notably
// [internal/kernelmod]) so this package contains no parsing or shell-out
// code of its own — a future preset for a different AF_ALG-family CVE
// can reuse the same internals by supplying a different module name.
//
// # Status
//
// v0.1 ships the five required checks. The advisory checks
// (kernel.version, hostinfo.os_release, afalg.no_active_users,
// integrity.su_binary) will land in v0.1.x and will appear at the tail
// of [All]'s returned slice — callers that switch on len(All()) MUST
// NOT do so; iterate the slice and dispatch on each check's ID.
package copyfail
