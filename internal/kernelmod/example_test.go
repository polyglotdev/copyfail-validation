// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod_test

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/internal/kernelmod"
)

// ExampleParseProcModules shows the typical use: open `/proc/modules`
// (or any io.Reader with the same shape) and iterate the parsed rows.
// The example uses a strings.NewReader so godoc can verify exact
// output bytes; production callers would pass the result of os.Open.
func ExampleParseProcModules() {
	r := strings.NewReader("algif_aead 16384 0 - Live 0x0000000000000000\nef_alg 32768 1 algif_aead Live 0x0000000000000000\n")

	mods, err := kernelmod.ParseProcModules(r)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	for _, m := range mods {
		fmt.Printf("%s size=%d refcount=%d state=%s usedby=%v\n", m.Name, m.Size, m.RefCount, m.State, m.UsedBy)
	}
	// Output:
	// algif_aead size=16384 refcount=0 state=Live usedby=[]
	// ef_alg size=32768 refcount=1 state=Live usedby=[algif_aead]
}

// ExampleParseProcModules_malformed shows the abort-on-bad behavior:
// a malformed line aborts parsing, the error wraps ErrMalformed (so
// callers can match with errors.Is), and the modules parsed before the
// failure are returned. This shape is deliberate — callers logging the
// audit get both the partial result AND a typed error to act on.
func ExampleParseProcModules_malformed() {
	r := strings.NewReader("algif_aead 16384 0 - Live 0x0\nthis line is broken\n")

	mods, err := kernelmod.ParseProcModules(r)
	fmt.Printf("parsed=%d malformed=%v\n", len(mods), errors.Is(err, kernelmod.ErrMalformed))
	// Output:
	// parsed=1 malformed=true
}

// ExampleIsLoaded shows the canonical query: parse the file, then ask
// "is module X loaded?" by name. Comparison is case-sensitive — the
// uppercase variant returns false even though the lowercase form is
// present.
func ExampleIsLoaded() {
	r := strings.NewReader("algif_aead 16384 0 - Live 0x0000000000000000\n")

	mods, err := kernelmod.ParseProcModules(r)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println(kernelmod.IsLoaded(mods, "algif_aead"))
	fmt.Println(kernelmod.IsLoaded(mods, "ALGIF_AEAD"))
	fmt.Println(kernelmod.IsLoaded(mods, "not_loaded"))
	// Output:
	// true
	// false
	// false
}

// ExampleParseConfReader shows the in-memory parser variant — useful
// when the conf content arrives over the network or from an embedded
// fixture. The Source string is recorded verbatim onto every emitted
// directive's Source field; callers passing real file content should
// pass the absolute path so audit logs can identify the file later.
func ExampleParseConfReader() {
	conf := strings.NewReader(
		"# disable AF_ALG kernel module\n" +
			"install algif_aead /bin/false\n" +
			"blacklist algif_aead\n",
	)

	directives, err := kernelmod.ParseConfReader(conf, "/etc/modprobe.d/disable-algif-aead.conf")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	for _, d := range directives {
		fmt.Printf("%s %s args=%v line=%d\n", d.Kind, d.Module, d.Args, d.LineNum)
	}
	// Output:
	// install algif_aead args=[/bin/false] line=2
	// blacklist algif_aead args=[] line=3
}

// ExampleParseConfReader_continuation shows that a trailing backslash
// joins the next line into one directive. The reported LineNum points
// at the FIRST line of the joined block — that is where an operator
// would edit to change the directive.
func ExampleParseConfReader_continuation() {
	conf := strings.NewReader(
		"options algif_aead \\\n" +
			"    foo=1 bar=2\n",
	)

	directives, err := kernelmod.ParseConfReader(conf, "demo.conf")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	d := directives[0]
	fmt.Printf("%s %s args=%v line=%d\n", d.Kind, d.Module, d.Args, d.LineNum)
	// Output:
	// options algif_aead args=[foo=1 bar=2] line=1
}

// ExampleInstallTarget shows the "later wins" semantics that mirror
// modprobe's conf-file precedence. An "install" directive in a
// higher-sorting file (or later in the same parse) shadows earlier
// ones for the same module. The found bool distinguishes "no install
// directive at all" from "install with empty target" — which is why
// callers must not just check `target == ""`.
func ExampleInstallTarget() {
	directives := []kernelmod.ConfDirective{
		{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: "00-blacklist.conf", LineNum: 1},
		{Kind: "install", Module: "algif_aead", Args: []string{"/bin/true"}, Source: "99-override.conf", LineNum: 1},
		{Kind: "blacklist", Module: "evil_module", Args: []string{}, Source: "00-blacklist.conf", LineNum: 2},
	}

	target, found := kernelmod.InstallTarget(directives, "algif_aead")
	fmt.Printf("algif_aead -> target=%q found=%v\n", target, found)

	target, found = kernelmod.InstallTarget(directives, "missing_module")
	fmt.Printf("missing_module -> target=%q found=%v\n", target, found)
	// Output:
	// algif_aead -> target="/bin/true" found=true
	// missing_module -> target="" found=false
}

// ExampleIsBlacklisted shows the monotonic semantics: a single
// blacklist directive ANYWHERE in any file makes the module
// blacklisted. There is no "un-blacklist" directive in the modprobe.d
// format, so blacklist precedence does NOT follow "later wins".
func ExampleIsBlacklisted() {
	directives := []kernelmod.ConfDirective{
		{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: "demo.conf", LineNum: 1},
		{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: "demo.conf", LineNum: 2},
	}

	fmt.Println(kernelmod.IsBlacklisted(directives, "algif_aead"))
	fmt.Println(kernelmod.IsBlacklisted(directives, "ALGIF_AEAD"))
	fmt.Println(kernelmod.IsBlacklisted(directives, "not_present"))
	// Output:
	// true
	// false
	// false
}

// ExampleDryRunModule shows the typical "is this module blocked?"
// flow using a FakeRunner: register the canned `modprobe -n -v algif_aead`
// output that a host with a `install algif_aead /bin/false` directive
// would produce, invoke DryRunModule, and inspect the parsed result.
// Production callers wire NewOSRunner from internal/exec instead — the
// FakeRunner is only used here so the example is hermetic and godoc
// can verify exact output bytes.
func ExampleDryRunModule() {
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"modprobe -n -v algif_aead": {
				Stdout:   []byte("install /bin/false \n"),
				ExitCode: 0,
			},
		},
	}

	dry, err := kernelmod.DryRunModule(context.Background(), runner, "algif_aead")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("resolved=%q blocked=%v\n", dry.ResolvedTo, dry.Blocked)
	// Output:
	// resolved="install /bin/false" blocked=true
}

// ExampleDryRunModule_loadable shows the inverse case: the module is
// loadable (no install directive blocks it), so modprobe -n -v emits
// an `insmod /lib/modules/.../algif_aead.ko` line. ResolvedTo holds
// the trimmed first line and Blocked is false because the canonical
// "install /bin/false" target was not the resolution.
func ExampleDryRunModule_loadable() {
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"modprobe -n -v algif_aead": {
				Stdout:   []byte("insmod /lib/modules/6.1.0-amzn2023/kernel/crypto/algif_aead.ko \n"),
				ExitCode: 0,
			},
		},
	}

	dry, err := kernelmod.DryRunModule(context.Background(), runner, "algif_aead")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("resolved=%q blocked=%v\n", dry.ResolvedTo, dry.Blocked)
	// Output:
	// resolved="insmod /lib/modules/6.1.0-amzn2023/kernel/crypto/algif_aead.ko" blocked=false
}
