// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package hostinfo_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/internal/hostinfo"
)

// ExampleParseOSRelease shows the typical use: open /etc/os-release
// (or any io.Reader with the same shape) and extract the (id,
// versionID, prettyName) tuple. Production callers pass the result
// of os.Open; this example uses strings.NewReader so godoc can
// verify exact output bytes.
func ExampleParseOSRelease() {
	r := strings.NewReader(`NAME="Amazon Linux"
ID="amzn"
VERSION_ID="2023"
PRETTY_NAME="Amazon Linux 2023.4.20240108"
`)

	id, versionID, prettyName, err := hostinfo.ParseOSRelease(r)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("id=%s\n", id)
	fmt.Printf("version_id=%s\n", versionID)
	fmt.Printf("pretty_name=%s\n", prettyName)
	// Output:
	// id=amzn
	// version_id=2023
	// pretty_name=Amazon Linux 2023.4.20240108
}

// ExampleParseOSRelease_quoteForms shows that the parser accepts all
// three quote forms documented by os-release(5): unquoted,
// double-quoted, single-quoted. All three produce the same result.
func ExampleParseOSRelease_quoteForms() {
	for _, line := range []string{
		"ID=ubuntu\n",
		`ID="ubuntu"` + "\n",
		`ID='ubuntu'` + "\n",
	} {
		id, _, _, _ := hostinfo.ParseOSRelease(strings.NewReader(line))
		fmt.Println(id)
	}
	// Output:
	// ubuntu
	// ubuntu
	// ubuntu
}

// ExampleGather demonstrates the typical caller pattern: construct a
// runner (NewOSRunner in production), call Gather, and consume the
// populated report.HostInfo. The example is intentionally compiled
// but NOT run by `go test` (no `// Output:` directive) because the
// returned HostInfo varies per host — a pinned Output line would be
// flaky on every CI runner.
//
// For a hermetic, runnable example see ExampleGather_withFakeRunner.
func ExampleGather() {
	runner := exec.NewOSRunner()

	host, err := hostinfo.Gather(context.Background(), runner)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("hostname=%s os=%s/%s kernel=%s arch=%s\n",
		host.Hostname, host.OSRelease, host.OSVersion, host.KernelRelease, host.Arch)
}

// ExampleGather_withFakeRunner shows the same flow with a
// FakeRunner pre-loaded with canned uname responses, so the example
// is hermetic and godoc can verify exact output bytes. Test code
// uses this pattern; production code uses the form in ExampleGather.
//
// The os-release content is written to a temp directory so this
// example does not depend on the host's real /etc/os-release.
func ExampleGather_withFakeRunner() {
	// Build a minimal fake etc/ tree.
	etcRoot, err := os.MkdirTemp("", "hostinfo-example-")
	if err != nil {
		fmt.Println("mkdtemp:", err)
		return
	}
	defer func() { _ = os.RemoveAll(etcRoot) }()
	if mkErr := os.MkdirAll(filepath.Join(etcRoot, "etc"), 0o750); mkErr != nil {
		fmt.Println("mkdir:", mkErr)
		return
	}
	osReleaseContent := []byte(`ID="amzn"` + "\n" + `VERSION_ID="2023"` + "\n")
	if wErr := os.WriteFile(filepath.Join(etcRoot, "etc", "os-release"), osReleaseContent, 0o600); wErr != nil {
		fmt.Println("write:", wErr)
		return
	}

	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"uname -r": {Stdout: []byte("6.1.66-91.160.amzn2023.x86_64\n"), ExitCode: 0},
			"uname -m": {Stdout: []byte("x86_64\n"), ExitCode: 0},
		},
	}

	host, err := hostinfo.GatherWithRootForTest(context.Background(), runner, etcRoot)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("os=%s/%s kernel=%s arch=%s\n",
		host.OSRelease, host.OSVersion, host.KernelRelease, host.Arch)
	// Output:
	// os=amzn/2023 kernel=6.1.66-91.160.amzn2023.x86_64 arch=x86_64
}
