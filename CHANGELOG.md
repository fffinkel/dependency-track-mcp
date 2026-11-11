# Changelog

Notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- Seven read-only tools: `find_projects`, `get_project_summary`, `list_project_findings`, `list_project_policy_violations`, `get_vulnerability`, `list_affected_projects`, `get_portfolio_summary`.
- stdio and streamable HTTP transports.
- Over HTTP, the caller's `X-Api-Key` or `Authorization: Bearer` header is forwarded to Dependency-Track.
