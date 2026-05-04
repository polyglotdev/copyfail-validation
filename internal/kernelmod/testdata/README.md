# kernelmod testdata

Fixture files used by `internal/kernelmod` parser tests. All files are read
verbatim by tests and `embed`/`os.ReadFile` callers — do not edit lines for
"clarity" without updating the corresponding test expectations.

## Provenance and anonymization

### `procmodules-al2023.txt`

A representative subset of `cat /proc/modules` from a stock Amazon Linux 2023
EC2 instance. Twenty lines covering the categories the parser must handle:

- modules with no users (`-` in the usedby column),
- modules with one user (`xt_conntrack` used by `nf_conntrack`),
- modules with multiple users (`af_alg`-style chains, here represented by
  `nf_defrag_ipv4`, `nf_defrag_ipv6`),
- a mix of small (16K) and large (1.7M `xfs`) sizes,
- the canonical AL2023 networking and crypto modules.

**Anonymization:** every kernel-space load address (the trailing
`0xffffffff…` token) was replaced with `0x0000000000000000`. The kernel
addresses are per-boot KASLR-randomized pointers — they leak host-specific
layout but carry no validation value, so we zero them out before commit.
The parser deliberately ignores the address column, so this anonymization
does not change parser behavior.

### `procmodules-empty.txt`

Zero-byte file. Pins the "empty input → empty slice, nil error" contract.

### `procmodules-with-algif.txt`

Five-line fixture with `algif_aead`, `algif_hash`, `algif_skcipher` plus
their shared `af_alg` parent and an unrelated `ext4` row. Used by the
`IsLoaded` test cases; addresses are zeroed for the same reason as above.
