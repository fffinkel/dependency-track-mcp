# Security

## Reporting a vulnerability

Report it privately through [GitHub security advisories](https://github.com/fffinkel/dependency-track-mcp/security/advisories/new). Do not open a public issue.

You should get a reply within a week. Fixes are released for the latest version only.

## What the server does with credentials

- It only makes GET requests to Dependency-Track. It has no tool that writes.
- It sends the Dependency-Track credential to the URL in `DTRACK_URL` and nowhere else.
- It does not log or store credentials, and it does not cache responses.
- Over HTTP it does no authentication of its own. A request is served with the credential it carries, or with `DTRACK_API_KEY` when that is set. If you set `DTRACK_API_KEY` on an HTTP deployment, restrict who can reach the server.
