// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package integrity is the pluggable file-integrity backend used by the
// integrity.su_binary check (spec §11) to verify a path against the
// owning package manager's manifest. It defines a single PkgMgr
// interface that both the rpm and dpkg backends implement, plus a
// Detect factory that selects an available backend at runtime — the
// same shape as database/sql drivers.
//
// Detection precedence (auto-selection rule):
//
//  1. RPM is tried first. The rationale is operational, not technical:
//     on a well-configured host both rpm and dpkg are mutually
//     exclusive in practice (a single distro uses one or the other),
//     but a small population of hybrid hosts (rpm-built containers
//     running on a dpkg base, or rare polyglot toolchains like alien)
//     have BOTH binaries on $PATH. In those rare cases the rpm
//     manifest is what the original package author signed; preferring
//     it minimizes false-positive "tampered" verdicts caused by dpkg
//     wrapping over a non-dpkg-installed file. RPM-first matches the
//     order the spec table in §11 lists ("rpm OR dpkg") and is what
//     audit consumers expect when reading Evidence["backend"].
//
//  2. DPKG is tried second.
//
//  3. If neither backend's binary resolves via internal/exec.ResolveCommand,
//     Detect returns ErrNoPkgManager and the integrity.su_binary check
//     records a Skip with reason="no supported package manager".
//
// Result shape: every PkgMgr.Verify returns the same VerifyResult
// struct so the integrity.su_binary check has a single, backend-agnostic
// type to read. Boolean fields are signed positive (true means there
// IS a problem) so callers use a single `if !result.Clean()` check
// rather than negating each field. RawOutput preserves the verbatim
// subprocess stdout/stderr for forensic recording into Evidence.
//
// All subprocess work happens through the exec.Runner interface so
// unit tests inject canned outputs via exec.FakeRunner without
// shelling out to real rpm/dpkg binaries. The trust boundary follows
// the same rules as kernelmod (spec §7): all caller-supplied path and
// package arguments are wrapped as exec.Untrusted and validated before
// the subprocess runs.
package integrity
