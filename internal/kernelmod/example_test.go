// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod_test

import (
	"errors"
	"fmt"
	"strings"

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
