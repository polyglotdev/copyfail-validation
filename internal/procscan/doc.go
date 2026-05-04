// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package procscan walks /proc/<pid>/maps to detect processes that have
// AF_ALG-family kernel modules mapped into their address space. It is
// the native, no-shell replacement for the legacy
// `lsof | grep -q AF_ALG; echo $?` pipeline used by the original
// copyfail prototype — that pipeline was both a textbook shell-injection
// vector AND an unnecessary external dependency. The implementation here
// reads /proc directly with the standard library, has zero external
// process invocations, and surfaces structured results suitable for
// inclusion in audit reports.
//
// # Threat-model rationale
//
// Why /proc/<pid>/maps and not netlink: AF_ALG sockets are NOT visible
// in /proc/net/tcp, /proc/net/unix, or any other /proc/net/* file. The
// kernel's algif accounting is reachable only via netlink queries that
// require CAP_NET_ADMIN — a capability this validator deliberately does
// not request. The maps-based heuristic implemented here is what is
// actually achievable from userspace and catches every realistic
// legitimate consumer (encrypted-filesystem daemons, hardware-offload
// crypto users) plus any malicious user that has the module mapped.
//
// Why root is required: a non-root caller's view of /proc only includes
// processes owned by that caller's UID. The kernel hides foreign-UID
// process directories from non-root readers — Scan would therefore see
// only its own /proc/self entry and miss every other process on the
// host. Rather than report misleading "all clear" results, Scan refuses
// to run unless EUID == 0 and returns ErrNotRoot. Callers should
// translate this into a Skip with reason
// "requires root to enumerate /proc/<pid>/maps for processes other than
// self" (spec §11).
//
// # Result completeness vs. fail-fast
//
// Per-PID I/O errors are intentionally non-fatal: a single unreadable
// process directory must not abort the whole scan. An audit run wants
// the FULL picture, even if some entries are missing. EACCES on a
// /proc/<pid>/maps read produces a UnreadablePIDs entry; ENOENT (a
// process exited mid-walk) is silently swallowed. Only preconditions
// (EUID, /proc itself) cause Scan to return without producing a
// ScanResult.
//
// # Spec reference
//
// See docs/superpowers/specs/2026-05-04-copyfail-validation-design.md
// §11 for the afalg.no_active_users parser contract — preconditions,
// algorithm, postconditions, and evidence shape.
package procscan
