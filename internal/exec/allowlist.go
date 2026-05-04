// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"fmt"
	"os"
	osexec "os/exec"
)

// allowedCommands maps a logical command name to its preferred absolute
// path. Lookup falls back to os/exec.LookPath only when the preferred
// path is missing on disk (e.g., on distros that put modprobe in
// /usr/sbin instead of /sbin). Adding a new entry here is a security
// review event — every binary on this list expands the package's attack
// surface and must be justified against the threat model in spec §7.
//
// The set tracks spec §7 exactly. Notably, lsof was REMOVED in this
// revision: the AF_ALG-active-users check now reads /proc/<pid>/fd/*
// directly (see spec §11), eliminating the only need for an external
// process for that path.
var allowedCommands = map[string]string{
	"modprobe":   "/sbin/modprobe",
	"lsmod":      "/sbin/lsmod",
	"uname":      "/bin/uname",
	"rpm":        "/usr/bin/rpm",
	"dpkg":       "/usr/bin/dpkg",
	"dpkg-query": "/usr/bin/dpkg-query",
	"debsums":    "/usr/bin/debsums",
	"sha256sum":  "/usr/bin/sha256sum",
}

// ResolveCommand returns the absolute path that should be executed for
// the logical command name, or an error.
//
// Resolution order:
//
//  1. If name is not in allowedCommands, return ErrCommandDenied. This
//     is the security gate: the binary may exist on $PATH but is not on
//     the allowlist, and adding a new entry requires a security review.
//  2. If the preferred absolute path exists (per os.Stat), return it.
//     Preferring the absolute path defends against $PATH hijacking.
//  3. Otherwise fall back to os/exec.LookPath, which honors $PATH. This
//     is the cross-distro fallback (e.g., /usr/sbin/modprobe on systemd
//     unified-bin distros). If that also fails, return ErrCommandNotFound.
//
// Callers should treat the returned path as opaque — it is recorded in
// Result.Path so audit logs can show exactly which binary ran.
func ResolveCommand(name string) (string, error) {
	preferred, ok := allowedCommands[name]
	if !ok {
		return "", fmt.Errorf("%w: %q (add to allowedCommands with security review)", ErrCommandDenied, name)
	}
	if _, err := os.Stat(preferred); err == nil {
		return preferred, nil
	}
	resolved, err := osexec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: %q (preferred=%s, PATH lookup failed: %v)", ErrCommandNotFound, name, preferred, err)
	}
	return resolved, nil
}
