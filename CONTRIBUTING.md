# Contributing

Issues and pull requests are welcome. For anything larger than a bug fix, open an issue first so we can agree on the shape before you write code.

## Rules for tools

These follow the direction the Dependency-Track maintainers gave in [dependency-track#5791](https://github.com/DependencyTrack/dependency-track/issues/5791). A pull request that adds or changes a tool must meet all four.

1. **Start from a question.** A tool exists because people ask a specific question, such as "where are we exposed to this CVE?". Name the question in the pull request. A tool that only mirrors a REST endpoint is not accepted.
2. **Bound the cost.** One call makes a small, fixed number of requests to Dependency-Track, whatever the size of the portfolio. State the maximum in the tool description (`Cost: ...`). If a question needs the whole portfolio, find the endpoint where Dependency-Track has already aggregated it, or do not add the tool.
3. **Say when a result is partial.** If a limit stopped a read early, the result says so (`truncated`, `complete`, `total`), so the model does not report a partial list as the whole answer.
4. **Leave access control to Dependency-Track.** Every request uses the caller's credential. Do not add a permission system, a cache shared between callers, or anything else that could show a caller data their credential cannot read.

The server is read-only. Tools that write (for example recording an analysis decision) need a design discussion in an issue first.

## Development

You need Go 1.25 or newer.

```sh
go test -race ./...
go vet ./...
gofmt -l .          # must print nothing
golangci-lint run   # optional locally, required in CI
```

Tests run against a fake Dependency-Track in `internal/tools/tools_test.go`. Add the endpoints your tool calls to it, and assert on the number of requests your tool makes.

To try a build against a real server:

```sh
go build -o dependency-track-mcp .
DTRACK_URL=https://dtrack.example.com DTRACK_API_KEY=... \
  npx @modelcontextprotocol/inspector ./dependency-track-mcp
```

## Pull requests

- Keep each pull request to one change.
- Add or update tests.
- Add a line to `CHANGELOG.md` under Unreleased.
- Do not put real project names, hostnames or vulnerability data from a private Dependency-Track instance in tests, issues or commits.

## Releases

Maintainers release by pushing a tag such as `v0.2.0`. The release workflow builds the binaries and the container image.

## Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
