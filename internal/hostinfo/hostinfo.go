// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package hostinfo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/report"
)

// osReleaseRelativePath is the path under the gather root where the
// os-release(5) file lives. Production code uses /etc as the root; tests
// pass a t.TempDir() so the parser is exercised without root.
const osReleaseRelativePath = "etc/os-release"

// productionEtcRoot is "/" — the directory whose `etc/os-release` is
// the real /etc/os-release. Kept as a named constant so the production
// vs test seam is explicit at every call site.
const productionEtcRoot = "/"

// Gather populates a report.HostInfo from the running host.
//
// Field sources:
//
//   - Hostname: os.Hostname() (returns the kernel-reported hostname).
//   - KernelRelease: `uname -r` via runner.
//   - OSRelease, OSVersion: parsed from /etc/os-release (the ID and
//     VERSION_ID fields respectively).
//   - Arch: `uname -m` via runner.
//
// Errors are wrapped with package context. A missing /etc/os-release is
// NOT fatal — the OSRelease/OSVersion fields are left empty and other
// fields still populate. A failed uname call IS fatal because without
// it we cannot identify the kernel for forensic purposes; the partial
// HostInfo gathered so far is still returned alongside the error so
// callers may include it in audit logs.
//
// The HostInfo's PrettyName is NOT exposed via the report.HostInfo
// wire shape (the report only carries OSRelease + OSVersion); the
// parser still extracts it for completeness so a future schema bump
// can surface it without revisiting the parser.
func Gather(ctx context.Context, runner exec.Runner) (report.HostInfo, error) {
	return gatherWithRoot(ctx, runner, productionEtcRoot)
}

// gatherWithRoot is the testable core of Gather. Production code calls
// Gather, which delegates here with etcRoot = "/". Tests call this
// function directly with a t.TempDir() containing an etc/os-release
// fixture so coverage doesn't require touching the host's real
// /etc/os-release.
//
// etcRoot is the directory the gather treats as if it were "/"; the
// os-release file is read from filepath.Join(etcRoot, "etc/os-release").
func gatherWithRoot(ctx context.Context, runner exec.Runner, etcRoot string) (report.HostInfo, error) {
	host := report.HostInfo{}

	// Hostname is the cheapest call — populate it first so a uname
	// failure still leaves a partial HostInfo with the hostname for
	// audit logs.
	if name, err := os.Hostname(); err == nil {
		host.Hostname = name
	}
	// os.Hostname errors are intentionally ignored: a hostname-less
	// host is unusual but not fatal, and the empty string already
	// signals "unknown" to downstream renderers. The audit log gets
	// the rest of the gathered fields either way.

	// /etc/os-release is OPTIONAL — minimal containers and embedded
	// images sometimes ship without one. A missing file leaves the
	// OSRelease/OSVersion fields empty and is not an error.
	osPath := filepath.Join(etcRoot, osReleaseRelativePath)
	if id, versionID, _, err := readOSReleaseFile(osPath); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return host, fmt.Errorf("hostinfo: parse os-release at %s: %w", osPath, err)
		}
		// File absent — leave fields empty per the documented contract.
	} else {
		host.OSRelease = id
		host.OSVersion = versionID
	}

	// uname is REQUIRED — without kernel release and arch the report
	// cannot be matched against a known-vulnerable kernel for forensic
	// purposes. We surface the underlying exec error verbatim.
	kernel, err := unameField(ctx, runner, exec.Trusted("-r"))
	if err != nil {
		return host, fmt.Errorf("hostinfo: uname -r: %w", err)
	}
	host.KernelRelease = kernel

	arch, err := unameField(ctx, runner, exec.Trusted("-m"))
	if err != nil {
		return host, fmt.Errorf("hostinfo: uname -m: %w", err)
	}
	host.Arch = arch

	return host, nil
}

// readOSReleaseFile opens the os-release file at path and parses it
// via ParseOSRelease. The file is opened with os.Open (not os.ReadFile)
// to keep memory bounded for the rare distro that ships an unusually
// large os-release file.
func readOSReleaseFile(path string) (id, versionID, prettyName string, err error) {
	f, err := os.Open(path) // #nosec G304 -- path is built from a controlled etcRoot in production; tests pass t.TempDir().
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = f.Close() }()

	return ParseOSRelease(f)
}

// unameField runs `uname <flag>` via the supplied Runner and returns
// the trimmed first line of stdout. The flag MUST be a Trusted exec
// arg (since callers always pass a hard-coded `-r` / `-m`); any other
// arg type would not pass the Untrusted leading-dash check and would
// be a programmer error.
//
// stderr is intentionally ignored on success — `uname` doesn't write
// to stderr unless the flag is invalid, which would also produce a
// non-zero exit and a wrapped error from the Runner.
func unameField(ctx context.Context, runner exec.Runner, flag exec.Arg) (string, error) {
	cmd := exec.Cmd{
		Name: "uname",
		Args: []exec.Arg{flag},
	}
	res, err := runner.Run(ctx, cmd)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("hostinfo: uname exited with code %d (stderr=%q)", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}
