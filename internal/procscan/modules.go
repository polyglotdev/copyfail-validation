// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package procscan

// AFAlgModules is the list of kernel module names whose presence in a
// process's memory map indicates AF_ALG-family socket usage. Comparison
// is case-sensitive substring on each /proc/<pid>/maps line — the
// kernel module path column is what the substring is matched against.
//
// Adding a new entry must go through security review — every name here
// triggers a Candidate report and (in the upstream check) a Fail or
// advisory result. Over-broad entries become noisy false-positives;
// missing entries become silent detection failures. The current set
// covers the entire AF_ALG family as of Linux 6.x (af_alg core +
// algif_aead, algif_skcipher, algif_hash, algif_rng frontends); future
// in-tree additions to the family will require a corresponding entry
// here.
//
// The slice is exported as a `var` (not a `const`) because Go does not
// support `const` slices, and as a slice (not a `[...]string` array)
// because the upstream check iterates it generically. Callers MUST NOT
// mutate this slice — the package treats it as immutable for the
// process lifetime.
var AFAlgModules = []string{
	"af_alg",
	"algif_aead",
	"algif_skcipher",
	"algif_hash",
	"algif_rng",
}
