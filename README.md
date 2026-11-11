# dependency-track-mcp

A read-only [Model Context Protocol](https://modelcontextprotocol.io/) server for [OWASP Dependency-Track](https://dependencytrack.org/). It lets an AI assistant such as Claude answer questions about your projects' vulnerabilities and policy violations.

It is a single Go binary. It is not affiliated with OWASP or the Dependency-Track project.

## Questions it answers

| Question | Tool | Requests to Dependency-Track per call |
|---|---|---|
| Which project is this application? | `find_projects` | 1 |
| How is this project doing? | `get_project_summary` | at most 2 |
| What is vulnerable in this project, worst first? | `list_project_findings` | at most 10 |
| Which policies does this project violate? | `list_project_policy_violations` | 1 |
| What is this CVE? | `get_vulnerability` | 1 |
| Where are we exposed to this CVE? | `list_affected_projects` | 1 |
| How is the whole portfolio doing? | `get_portfolio_summary` | 1 |

## Install

With Go 1.25 or newer:

```sh
go install github.com/fffinkel/dependency-track-mcp@latest
```

Or download a binary for Linux, macOS or Windows from the [releases page](https://github.com/fffinkel/dependency-track-mcp/releases), or use the container image `ghcr.io/fffinkel/dependency-track-mcp`.

## Set up

You need the URL of your Dependency-Track API server and an API key. Create the key in Dependency-Track under Administration > Access Management > Teams, on a team with these permissions:

- `VIEW_PORTFOLIO`
- `VIEW_VULNERABILITY`
- `VIEW_POLICY_VIOLATION`

### Claude Code

```sh
claude mcp add dependency-track \
  -e DTRACK_URL=https://dtrack.example.com \
  -e DTRACK_API_KEY=your-api-key \
  -- dependency-track-mcp
```

### Claude Desktop and other clients

Add this to the client's MCP configuration:

```json
{
  "mcpServers": {
    "dependency-track": {
      "command": "dependency-track-mcp",
      "env": {
        "DTRACK_URL": "https://dtrack.example.com",
        "DTRACK_API_KEY": "your-api-key"
      }
    }
  }
}
```

With the container image, use `"command": "docker"` and `"args": ["run", "-i", "--rm", "-e", "DTRACK_URL", "-e", "DTRACK_API_KEY", "ghcr.io/fffinkel/dependency-track-mcp"]`.

### Shared server over HTTP

Run one server for a team instead of one per person:

```sh
DTRACK_URL=https://dtrack.example.com dependency-track-mcp -http 127.0.0.1:8080
```

MCP is served at `/mcp` and a health check at `/healthz`. Each person connects with their own Dependency-Track credential, which the server forwards:

```sh
claude mcp add --transport http dependency-track http://127.0.0.1:8080/mcp \
  -H "X-Api-Key: your-api-key"
```

`Authorization: Bearer <token>` works too, with a Dependency-Track session token.

If you also set `DTRACK_API_KEY` on the server, requests that carry no credential use that key. People then need no key of their own, but everyone who can reach the server sees what that key sees. See [Access control](#access-control).

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `DTRACK_URL` | Dependency-Track API server URL | required |
| `DTRACK_API_KEY` | API key for requests that bring no credential | required over stdio, optional over HTTP |
| `DTRACK_MCP_HTTP_ADDR` | Listen address for HTTP, same as `-http` | unset (stdio) |
| `DTRACK_MCP_TIMEOUT` | Timeout for each request to Dependency-Track | `30s` |
| `DTRACK_MCP_MAX_CONCURRENCY` | Requests to Dependency-Track in flight at once, across all callers | `4` |

## Design

The Dependency-Track maintainers discussed an MCP server in [dependency-track#5791](https://github.com/DependencyTrack/dependency-track/issues/5791). Their points were that wrapping the REST API one endpoint per tool works badly on large portfolios, that tools should be designed from the questions people ask, that expensive queries must not overload the server, and that access control must hold. This server is built to those points.

**Tools come from questions.** There is no generic "call this endpoint" tool. Each tool answers one question from the table above and returns a short, sorted result.

**Cost is bounded.** Every tool makes a fixed maximum number of requests, stated in its description, whatever the size of the portfolio. Portfolio-wide questions use endpoints where Dependency-Track has already done the aggregation: `get_portfolio_summary` reads precomputed metrics, and `list_affected_projects` asks Dependency-Track which projects carry a vulnerability instead of reading projects one by one. No tool walks the portfolio.

**Partial results say so.** `list_project_findings` reads at most 1,000 findings of a project. Results include `total`, `truncated` or `complete`, so the assistant can tell a full answer from a partial one.

**Load is limited.** `DTRACK_MCP_MAX_CONCURRENCY` caps requests in flight across all callers, and each request has a timeout. Nothing is retried.

**Read-only.** The server only makes GET requests. Recording analysis decisions or suppressing findings is out of scope for now.

### Access control

The server has no permission system. Every request to Dependency-Track is made with a Dependency-Track credential, and Dependency-Track decides what that credential can read, including portfolio access control. Nothing is cached, so one caller never receives data fetched for another.

- Over stdio, the credential is `DTRACK_API_KEY`: your key, your view.
- Over HTTP, the credential is the one each request carries. This keeps per-person access control intact.
- Over HTTP with `DTRACK_API_KEY` set, requests without a credential share that key. This is convenient and it gives up per-person access control. Use a read-only key, and restrict who can reach the server. The server does not authenticate callers itself.

### Read replicas

The maintainers noted that some agent queries may need to be served from a database read replica. Dependency-Track does not offer that as an option today, as far as this project knows. If your deployment has an API server instance for read traffic, point `DTRACK_URL` at it.

## Compatibility

Tested against Dependency-Track 5.1.2. The server uses only the v1 REST API. Dependency-Track 4.x serves the same endpoints, but this project has not been tested against it yet. Reports are welcome.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), in particular the rules a new tool must meet. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
