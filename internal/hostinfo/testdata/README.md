# hostinfo testdata

Fixture files used by `internal/hostinfo` parser and Gather tests. All
files are read verbatim by tests via `os.ReadFile` — do not edit lines
for "clarity" without updating the corresponding test expectations.

## Provenance and anonymization

The `os-release(5)` files in this directory are reproduced from the
contents of `/etc/os-release` on stock distribution images. The
`os-release` file is published by each distribution under its OS license
and contains no host-specific identifiers — there is **no anonymization
needed**, every byte is the same on every freshly-installed instance of
the corresponding distribution.

### `os-release-al2023`

The `/etc/os-release` from a stock Amazon Linux 2023 EC2 instance (image
`al2023-ami-2023.4.20240108`). Asserts:

- `ID="amzn"`
- `VERSION_ID="2023"`
- `PRETTY_NAME="Amazon Linux 2023.4.20240108"`

### `os-release-ubuntu2204`

The `/etc/os-release` from a stock Ubuntu 22.04.3 LTS image. Notably
mixes quoted and unquoted values (`ID=ubuntu` is unquoted; `PRETTY_NAME`
is double-quoted) — exercises both shapes in one fixture. Asserts:

- `ID="ubuntu"`
- `VERSION_ID="22.04"`
- `PRETTY_NAME="Ubuntu 22.04.3 LTS"`

### `os-release-rocky9`

The `/etc/os-release` from a stock Rocky Linux 9.3 (Blue Onyx) image.
Asserts:

- `ID="rocky"`
- `VERSION_ID="9.3"`
- `PRETTY_NAME="Rocky Linux 9.3 (Blue Onyx)"`
