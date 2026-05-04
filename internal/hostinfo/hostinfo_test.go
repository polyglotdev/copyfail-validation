// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package hostinfo_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/internal/hostinfo"
)

// gatherFixture describes one Gather scenario: the etc/os-release
// content to write under t.TempDir() (or "" to skip writing the file
// entirely, simulating a host without /etc/os-release), plus the
// canned uname responses to feed into FakeRunner.
//
// Field order is laid out for govet's fieldalignment pass: 16-byte
// interface headers first (errors are 2 words), then 16-byte string
// headers, then the 1-byte bool tail. This keeps the GC-scannable
// pointer prefix tightly packed.
type gatherFixture struct {
	unameRError       error
	unameMError       error
	osReleaseContent  string
	unameRStdout      string
	unameMStdout      string
	skipOSReleaseFile bool
}

// buildGatherFixture materializes f under a fresh t.TempDir() and
// returns the etcRoot path plus a FakeRunner pre-loaded with the canned
// uname responses. The runner's Calls slice is left initialized so
// tests can assert on the exact (Cmd.Name, Args) shape of each call.
func buildGatherFixture(subT *testing.T, f gatherFixture) (string, *exec.FakeRunner) {
	subT.Helper()

	etcRoot := subT.TempDir()
	if !f.skipOSReleaseFile {
		etcDir := filepath.Join(etcRoot, "etc")
		if err := os.MkdirAll(etcDir, 0o750); err != nil {
			subT.Fatalf("mkdir %s: %v", etcDir, err)
		}
		path := filepath.Join(etcDir, "os-release")
		if err := os.WriteFile(path, []byte(f.osReleaseContent), 0o600); err != nil {
			subT.Fatalf("write %s: %v", path, err)
		}
	}

	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"uname -r": {Stdout: []byte(f.unameRStdout), ExitCode: 0},
			"uname -m": {Stdout: []byte(f.unameMStdout), ExitCode: 0},
		},
		Errors: map[string]error{},
	}
	if f.unameRError != nil {
		runner.Errors["uname -r"] = f.unameRError
	}
	if f.unameMError != nil {
		runner.Errors["uname -m"] = f.unameMError
	}
	return etcRoot, runner
}

// TestGatherWithRoot covers the full Gather contract: happy-path
// population from a real os-release fixture, missing /etc/os-release
// (non-fatal), uname -r failure (fatal), uname -m failure (fatal),
// and the call-shape assertion that uname is invoked with exactly
// `-r` and `-m` as Trusted args.
func TestGatherWithRoot(t *testing.T) {
	t.Parallel()

	const al2023OSRelease = "ID=\"amzn\"\nVERSION_ID=\"2023\"\nPRETTY_NAME=\"Amazon Linux 2023.4.20240108\"\n"

	tests := []struct {
		name              string
		wantOSRelease     string
		wantOSVersion     string
		wantKernelRelease string
		wantArch          string
		fixture           gatherFixture
	}{
		{
			name: "happy path populates all fields",
			fixture: gatherFixture{
				osReleaseContent: al2023OSRelease,
				unameRStdout:     "6.1.66-91.160.amzn2023.x86_64\n",
				unameMStdout:     "x86_64\n",
			},
			wantOSRelease:     "amzn",
			wantOSVersion:     "2023",
			wantKernelRelease: "6.1.66-91.160.amzn2023.x86_64",
			wantArch:          "x86_64",
		},
		{
			name: "missing /etc/os-release leaves OS fields empty but populates uname",
			fixture: gatherFixture{
				skipOSReleaseFile: true,
				unameRStdout:      "5.15.0-91-generic\n",
				unameMStdout:      "aarch64\n",
			},
			wantOSRelease:     "",
			wantOSVersion:     "",
			wantKernelRelease: "5.15.0-91-generic",
			wantArch:          "aarch64",
		},
		{
			// uname -r failure aborts BEFORE uname -m; OSRelease and
			// OSVersion (parsed earlier) are still populated in the
			// partial HostInfo per the documented partial-result
			// contract. KernelRelease is empty because the failing
			// uname -r never wrote to host.KernelRelease.
			name: "uname -r failure aborts with wrapped error and partial result",
			fixture: gatherFixture{
				osReleaseContent: al2023OSRelease,
				unameRStdout:     "",
				unameRError:      errors.New("exec failed"),
				unameMStdout:     "x86_64\n",
			},
			wantOSRelease:     "amzn",
			wantOSVersion:     "2023",
			wantKernelRelease: "",
			wantArch:          "",
		},
		{
			// uname -m failure leaves Arch empty but KernelRelease
			// (set by the earlier successful uname -r) is preserved
			// in the partial HostInfo.
			name: "uname -m failure aborts with wrapped error and partial result",
			fixture: gatherFixture{
				osReleaseContent: al2023OSRelease,
				unameRStdout:     "6.1.66-91.160.amzn2023.x86_64\n",
				unameMStdout:     "",
				unameMError:      errors.New("exec failed"),
			},
			wantOSRelease:     "amzn",
			wantOSVersion:     "2023",
			wantKernelRelease: "6.1.66-91.160.amzn2023.x86_64",
			wantArch:          "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			etcRoot, runner := buildGatherFixture(subT, tc.fixture)

			host, err := hostinfo.GatherWithRootForTest(context.Background(), runner, etcRoot)

			switch {
			case tc.fixture.unameRError != nil || tc.fixture.unameMError != nil:
				if err == nil {
					subT.Fatalf("Gather() error = nil; want non-nil for uname failure scenario")
				}
			case err != nil:
				subT.Fatalf("Gather() unexpected error: %v", err)
			}

			if got, want := host.OSRelease, tc.wantOSRelease; got != want {
				subT.Errorf("OSRelease = %q; want %q", got, want)
			}
			if got, want := host.OSVersion, tc.wantOSVersion; got != want {
				subT.Errorf("OSVersion = %q; want %q", got, want)
			}
			if got, want := host.KernelRelease, tc.wantKernelRelease; got != want {
				subT.Errorf("KernelRelease = %q; want %q", got, want)
			}
			if got, want := host.Arch, tc.wantArch; got != want {
				subT.Errorf("Arch = %q; want %q", got, want)
			}
		})
	}
}

// TestGatherWithRoot_HostnameAlwaysSet verifies that Gather populates
// Hostname from os.Hostname(). The test does NOT pin the value (it
// could be anything depending on the host) — it only asserts the
// field is populated when os.Hostname() succeeds, which it always
// does on the CI runners we target.
func TestGatherWithRoot_HostnameAlwaysSet(t *testing.T) {
	t.Parallel()

	etcRoot, runner := buildGatherFixture(t, gatherFixture{
		osReleaseContent: "ID=test\nVERSION_ID=1\n",
		unameRStdout:     "test-kernel\n",
		unameMStdout:     "test-arch\n",
	})

	host, err := hostinfo.GatherWithRootForTest(context.Background(), runner, etcRoot)
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	osHostname, hnErr := os.Hostname()
	if hnErr != nil {
		t.Skipf("os.Hostname() failed on this runner: %v", hnErr)
	}
	if host.Hostname != osHostname {
		t.Errorf("Hostname = %q; want %q (from os.Hostname())", host.Hostname, osHostname)
	}
}

// TestGatherWithRoot_UnameCallShape pins the exec.Cmd shape that
// Gather hands to the runner. uname is invoked TWICE — once with
// `-r` and once with `-m` — and both args MUST be exec.Trusted (since
// they are hard-coded constants, not user input). A future maintainer
// who accidentally wraps `-r` in exec.Untrusted would see the test
// fail — Untrusted refuses leading-dash values and the call would
// be rejected by the runner's validateAll path.
func TestGatherWithRoot_UnameCallShape(t *testing.T) {
	t.Parallel()

	etcRoot, runner := buildGatherFixture(t, gatherFixture{
		osReleaseContent: "ID=test\nVERSION_ID=1\n",
		unameRStdout:     "test-kernel\n",
		unameMStdout:     "test-arch\n",
	})

	if _, err := hostinfo.GatherWithRootForTest(context.Background(), runner, etcRoot); err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	if got, want := len(runner.Calls), 2; got != want {
		t.Fatalf("FakeRunner.Calls len = %d; want %d", got, want)
	}

	for i, want := range []string{"-r", "-m"} {
		c := runner.Calls[i]
		if c.Name != "uname" {
			t.Errorf("Calls[%d].Name = %q; want %q", i, c.Name, "uname")
		}
		if len(c.Args) != 1 {
			t.Fatalf("Calls[%d].Args len = %d; want 1", i, len(c.Args))
		}
		// The arg MUST be a Trusted string — Untrusted refuses
		// leading-dash values and cannot represent `-r` or `-m`.
		if _, ok := c.Args[0].(exec.Trusted); !ok {
			t.Errorf("Calls[%d].Args[0] type = %T; want exec.Trusted", i, c.Args[0])
		}
		if c.Args[0].String() != want {
			t.Errorf("Calls[%d].Args[0] = %q; want %q", i, c.Args[0].String(), want)
		}
	}
}

// TestGatherWithRoot_NonExistentOSRelease_NonFatal verifies that a
// missing /etc/os-release file is NOT treated as a fatal error. The
// gather still returns a populated HostInfo (with empty OSRelease /
// OSVersion) and a nil error. The test creates an empty TempDir
// without writing the etc/ subdirectory, so the os-release ReadFile
// returns ENOENT, which the gather must tolerate.
func TestGatherWithRoot_NonExistentOSRelease_NonFatal(t *testing.T) {
	t.Parallel()

	etcRoot, runner := buildGatherFixture(t, gatherFixture{
		skipOSReleaseFile: true,
		unameRStdout:      "5.15.0\n",
		unameMStdout:      "x86_64\n",
	})

	host, err := hostinfo.GatherWithRootForTest(context.Background(), runner, etcRoot)
	if err != nil {
		t.Fatalf("Gather() unexpected error for missing /etc/os-release: %v", err)
	}
	if host.OSRelease != "" {
		t.Errorf("OSRelease = %q; want empty (no /etc/os-release)", host.OSRelease)
	}
	if host.OSVersion != "" {
		t.Errorf("OSVersion = %q; want empty (no /etc/os-release)", host.OSVersion)
	}
	if host.KernelRelease == "" {
		t.Errorf("KernelRelease = %q; want non-empty (uname succeeded)", host.KernelRelease)
	}
}

// TestGatherWithRoot_OSReleaseTrimsTrailingNewline verifies that the
// kernel release and arch fields have their trailing newlines trimmed.
// `uname -r` always emits a trailing newline; the report wire shape
// must NOT carry it because every downstream consumer (slog, JSON,
// Prometheus) would then have to trim it again.
func TestGatherWithRoot_OSReleaseTrimsTrailingNewline(t *testing.T) {
	t.Parallel()

	etcRoot, runner := buildGatherFixture(t, gatherFixture{
		osReleaseContent: "ID=test\n",
		unameRStdout:     "  6.1.66\n\n",
		unameMStdout:     "x86_64\n",
	})

	host, err := hostinfo.GatherWithRootForTest(context.Background(), runner, etcRoot)
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	if got, want := host.KernelRelease, "6.1.66"; got != want {
		t.Errorf("KernelRelease = %q; want %q (trailing whitespace must be trimmed)", got, want)
	}

	// Defensive: ensure no embedded newline survives in any field.
	for name, val := range map[string]string{
		"OSRelease":     host.OSRelease,
		"KernelRelease": host.KernelRelease,
		"Arch":          host.Arch,
	} {
		if strings.ContainsAny(val, "\n\r") {
			t.Errorf("%s = %q contains a newline; gather must trim", name, val)
		}
	}
}
