// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package kernelmod parses kernel-module-related files under /proc and
// /etc, and provides safe wrappers around modprobe-family commands via
// internal/exec. The parsers in this package are pure — they read from
// io.Reader so tests inject fixtures directly without shelling out.
//
// The package replaces the legacy shell pipeline that grepped
// `/proc/modules`, scanned `/etc/modprobe.d`, and invoked
// `modprobe -nv` through sh. Each of those steps is now a typed,
// allocation-bounded Go function: callers pass an io.Reader (for the
// pure parsers) or an exec.Runner (for the modprobe wrapper) and get
// back structured records plus sentinel errors. Tests inject fixtures
// or fakes; production code wires the real /proc + os/exec.
//
// See spec §7 for the rationale behind eliminating the shell pipeline
// and the trust boundary around modprobe output.
package kernelmod
