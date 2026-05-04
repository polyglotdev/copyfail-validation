# examples/redact-evidence

Demonstrates `internal/redact` on a sample evidence string that mixes:

- AWS credential env-var dumps (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
- HTTP `Authorization: Bearer <jwt>` headers (regression test for the original `\S+` regex bug that consumed only "Bearer" and leaked the JWT)
- Prose mentions of secret-keywords without separators (must NOT be redacted — false positives erode operator trust in the redactor)

## Run

```bash
go run ./examples/redact-evidence
```

## Use case

Use this as a sanity check before extending `redact.RedactionPattern`: edit `sample` to include the new pattern you want covered, run, and confirm the redactor handles it. Once the pattern is correct, port it to the test corpus under `internal/redact/testdata/` so it stays pinned.
