# 0008. Blocking HTTP client; tokio only as the MCP runtime

- Status: Accepted (2026-11-23)
- Implementation: Partly in place (phase 1): blocking `ureq` with rustls behind the egress guard in `src/http.rs`, with no async code in the HTTP path. Planned: the `rmcp` server, its tokio runtime, the `spawn_blocking` calls and the bounded parallel search, all in phase 3.

## Context

The server is one local process serving one user, so Gmail work is a handful of sequential requests, not high concurrency. `rmcp`, the official MCP SDK (0004), runs on tokio, so an async runtime is in the tree whatever HTTP client is chosen. The egress guard (0003) has to stay one small function that is easy to audit, and the OAuth library's HTTP hook, `SyncHttpClient`, is synchronous.

## Decision

- Gmail and OAuth calls use blocking `ureq` 3 with rustls, through the single egress function. The HTTP path contains no async code.
- tokio is present because `rmcp` needs it: a current-thread runtime that serves the MCP session. Tool handlers call the blocking client through `spawn_blocking`.
- A search fans its per-thread reads out with bounded parallelism (scoped threads, five at a time), not with async tasks.
- Rejected: an async HTTP client such as `reqwest` or `hyper` (a second HTTP stack, 0004), and a multi-thread runtime "for performance": the work is network-bound and one user's mailbox does not need it.

## Consequences

- The guard stays a plain synchronous function, and the same function serves as the OAuth library's HTTP client (0003).
- Cost: each in-flight request occupies a blocking thread (at most five at a time for a search) and there is no HTTP/2 multiplexing. At this scale that should not matter; this is an expectation, not a measurement, until phase 3 exists.
- tokio and its dependencies stay in the tree because `rmcp` needs them (72 crates for `rmcp` plus tokio, measured 2026-11-23; 0004). This decision limits how the runtime is used, not whether it is present.
- A change that swaps in async HTTP or a multi-thread runtime for speed would bring back the second HTTP stack that `deny.toml` bans by name.

## What would change this decision

- `rmcp` offering a runtime-free server transport, which would let tokio go.
- A measured latency problem in real use that bounded blocking parallelism cannot fix.
- `ureq` losing maintenance (0004).

## References

- [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md), [0004-dependency-policy-and-libraries.md](0004-dependency-policy-and-libraries.md)
- [deny.toml](../../deny.toml)
