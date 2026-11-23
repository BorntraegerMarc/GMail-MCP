# 0009. MCP over stdio only, no network-exposed endpoint

- Status: Accepted (2026-11-23)
- Implementation: Not implemented yet; only the scaffold exists. Planned: the OAuth loopback listener in phase 2; the stdio transport (`rmcp` with its stdio transport only) in phase 3.

## Context

The project's pitch is a local-only server. An MCP server can be reached in two ways: as a child process that talks over stdin and stdout, which is how Claude Desktop starts it, or as a network endpoint over an HTTP-based MCP transport. The second would open a listening socket in a process that holds Gmail credentials. A request for "remote use" is the likeliest well-meant feature request.

## Decision

- The server speaks MCP over stdio only, through `rmcp`'s stdio transport. It has no HTTP, SSE or other network transport and no remote mode.
- The only socket the project opens for listening is the OAuth loopback listener that `gmail-mcp auth` runs during consent: `127.0.0.1` only, an ephemeral port, with the `state` parameter checked (0003). `serve` listens on nothing.
- stdout belongs to the MCP protocol, so nothing else writes to it and logging goes to stderr only (the clippy print lints in `Cargo.toml` enforce this; 0006).
- Rejected: an HTTP transport for remote use. It would need authentication, transport security and binding decisions that make it a different project, and it would make a credential-holding process reachable over a network.

## Consequences

- There is no network-reachable MCP endpoint, so the protocol surface is whatever the local host process sends. Any process of the same user can still run the binary.
- The server works only with MCP hosts that start local processes, and cannot be shared across machines.
- One process serves one session, so there is no multi-tenant case to secure.

## What would change this decision

A remote use case whose threat model (authentication, transport security, binding) is written up and accepted in a new record that supersedes this one.

## References

- [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md), [0006-credentials-in-os-credential-store.md](0006-credentials-in-os-credential-store.md)
- [Cargo.toml](../../Cargo.toml) (lints)
