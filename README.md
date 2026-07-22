# govulncheck-ignore

`govulncheck-ignore` adds a small, reviewable ignore policy to Go's
[`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) command.

The native command deliberately has no support for silencing individual
findings. This wrapper runs its machine-readable scan, removes reviewed
vulnerability IDs from the failing set, and prints traces only for findings
that remain actionable.

## Install

Install `govulncheck` and this wrapper:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/dc-tec/govulncheck-ignore@latest
```

Pin both versions in CI rather than installing `@latest` there.

## Ignore policy

Create `.govulnignore` in the module root:

```text
# GO-2026-5662 affects a web UI that this service does not build or expose.
# Reviewed in SECURITY.md on 2026-07-22.
GO-2026-5662
```

The format is intentionally small:

- one `GO-YYYY-NNNN` vulnerability ID per line;
- blank lines are ignored;
- lines beginning with `#` are comments;
- malformed entries fail the scan.

Keep the reason, affected surface, review date, and remediation trigger in
comments or a linked security document. An ignore entry is an accepted risk,
not evidence that the advisory is harmless everywhere.

## Usage

Scan the current module:

```sh
govulncheck-ignore ./...
```

Use another policy or `govulncheck` binary:

```sh
govulncheck-ignore \
  -ignore config/reviewed-vulnerabilities.txt \
  -govulncheck ./bin/govulncheck \
  ./...
```

Pass native scan options after `--`:

```sh
govulncheck-ignore -- -tags=integration ./...
govulncheck-ignore -- -test ./...
govulncheck-ignore -- -mode=binary ./bin/service
```

`-format`, `-json`, `-show`, and `-version` are controlled by the wrapper and
cannot be forwarded.

To inspect traces for findings that are currently ignored:

```sh
govulncheck-ignore -show-ignored ./...
```

## Exit codes

|  Code | Meaning                                                            |
| ----: | ------------------------------------------------------------------ |
|     0 | No findings, or every finding is ignored                           |
|     1 | At least one unignored vulnerability was found                     |
|     2 | Wrapper configuration, execution, parsing, or trace-format failure |
| other | Unexpected `govulncheck` exit code, preserved by the wrapper       |

The wrapper fails closed if structured output cannot be decoded or an
unignored finding cannot be matched in the trace output.

## How it works

1. Run `govulncheck -format=json` and collect unique OSV IDs at the requested
   scan level. Lower-precision module/package messages emitted during a symbol
   scan are not treated as affected findings.
2. Subtract IDs listed in the ignore file.
3. If actionable findings remain, rerun with `-show=traces`.
4. Print only matching vulnerability blocks and exit with code 1.

Current machine-readable `govulncheck` formats exit successfully even when
they contain findings, so this tool owns the final policy exit code.

## Development

```sh
go test ./...
go vet ./...
go build ./...
```

The implementation uses only the Go standard library.

## Provenance and license

Licensed under Apache-2.0. See `LICENSE` and `NOTICE`.
