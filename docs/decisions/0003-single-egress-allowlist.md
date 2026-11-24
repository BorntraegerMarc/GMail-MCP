# 0003. Single egress function with an allowlist

- Status: Accepted (2026-11-23)
- Implementation: Partly in place (phase 1). The egress function is `src/http.rs` and its route table is in `src/policy.rs`. `tests/egress_policy.rs` holds a table of allowed and refused requests, parsing tricks included. `tests/static_policy.rs` scans `src/` for forbidden endpoints, methods, scopes, hosts, network and process APIs, and printing. `deny.toml` bans other HTTP and TLS crates and a second `ureq`. Planned in phase 2: the loopback listener with `src/auth.rs` (which is then added to the files the scan lets touch sockets) and the OAuth HTTP adapter.

## Context

The README's security table lists "Silent exfiltration by the server" (the fourth row) and answers it with one egress function that allows only two Google hosts and a fixed method and path allowlist, plus no telemetry. The README also states that the only write is creating a draft. Claims like these are worth something only if a reviewer can check them quickly, and that is not possible if any module may open a connection.

Allowing hosts alone would not be enough, because the Gmail host also serves the calls this server must never make (send, delete, filters, settings). Google offers no draft-only scope, and `gmail.compose` technically permits sending at the API level. So "nothing is sent" rests on the code never calling a send endpoint, backed by an allowlist and tests, and not on the scope alone.

## Decision

All outbound network I/O goes through one egress function (the guard) in one module, `src/http.rs`. It works as follows:

- Transport: HTTPS only, no redirects, no proxy, caps on response size, request size and request time. A followed redirect could reach a host the allowlist never checked, a proxy adds a hop the guard does not control, and the caps bound what a hostile or broken response can consume.
- Allowlist: only listed (host, method, path) combinations pass; everything else is refused. `oauth2.googleapis.com` serves token calls; `gmail.googleapis.com` serves GET reads of labels, threads and messages and one write, a POST that creates a draft. Every entry matches an exact path shape, segment by segment, never a prefix, so a path below an allowed one (such as an attachment download below a message) is not routable. The table lives in the code, not here.
- Mode: in read-only mode the guard refuses the draft route too, so a bug in the tool list alone cannot create a draft (0002-two-layer-permission-model.md).
- URL grammar: narrower than a URL parser, so there is no room for a difference between this check and the HTTP client. The URL must be exactly `https://<allowed host>/<path>` with an optional query, in printable ASCII, with no fragment, user info, port, upper case or trailing dot in the host.
- Headers: callers may set only `Authorization`, `Content-Type` and `Accept`. A caller-set `Host` header could aim an allowed address at another site.
- IDs: message and thread IDs are validated against a strict pattern before they enter a URL, so an ID cannot inject a path such as `../settings/filters` into an allowed shape.
- OAuth: the OAuth library's traffic passes through the guard too, because we implement its `SyncHttpClient` trait ourselves. Its built-in `ureq` feature would bypass the guard and pulls a second `ureq` major version.
- Excluded hosts: `www.googleapis.com` (it appears only inside OAuth scope strings) and `accounts.google.com` (only the consent URL the user's browser opens; the code never connects to it).

The OAuth redirect listener in `src/auth.rs` is the one other place allowed to touch sockets: it accepts connections and must never dial out. It binds `127.0.0.1` only, so other machines cannot connect, and rejects a redirect whose `state` it did not issue, because other software on the same machine still can connect.

A source-scanning test (`tests/static_policy.rs`) fails the build on forbidden endpoints, verbs, scopes and hosts, and on network or process APIs outside `src/http.rs` and `src/auth.rs`, so drift from single egress is caught by CI and not only by reviewers noticing.

Library alternatives (`reqwest`, `hyper`, `google-gmail1`) are rejected in `0004-dependency-policy-and-libraries.md`.

## Consequences

- The no-write and allowed-host claims can be checked in one module and its allowlist, plus the listener in `src/auth.rs` once it exists (see Limit). A new host, method or path shape is a visible edit to the route table in review (process: `CONTRIBUTING.md` rule 2), and a new write also fails the unit test that pins the table's writes. Because reads match exact shapes, "attachments are metadata only" holds in the allowlist and not only in tool code: no route admits an attachment download.
- The guard overlaps on purpose with what the OAuth scopes already restrict (defense in depth; see `0002-two-layer-permission-model.md` and the compose case in Context). Do not drop the guard, or an allowlist entry, as redundant.
- Cost: we own an adapter for the OAuth library's HTTP trait. The guard fails closed, so if Google moves an endpoint, calls break until the allowlist is updated, and a network that requires a proxy is not supported.
- Limit: single egress is held by review and a source scan, not by the type system or the OS. The guard sees only traffic routed through it and the scan reads only this project's source text, so neither stops a compromised dependency, or code here that takes a route the scan does not list, from opening its own connection.
- Limit: the scan will allow network imports in `src/auth.rs` as a whole once the listener lands (phase 2), so review will treat any outbound call there as a guard bypass.
- Limit: nothing in the build proves that the proxy setting is off. The client reads proxy variables from the environment unless told not to, and a test cannot set them without `unsafe`, so the override is held by review and its comment in `src/http.rs`.

## What would change this decision

- Google changes or versions the Gmail API paths. The allowlist follows in code, tests and README; this record changes only if the guard's design has to.
- A genuinely needed new read endpoint. It needs its own ADR and an allowlist edit in the same PR. A new write is not a candidate: `CONTRIBUTING.md` rule 1 allows no write beyond creating a draft.

## References

- Decision records: [0002-two-layer-permission-model.md](0002-two-layer-permission-model.md), [0004-dependency-policy-and-libraries.md](0004-dependency-policy-and-libraries.md)
- Repo files: [README.md](../../README.md) (security table, honest limits), [CONTRIBUTING.md](../../CONTRIBUTING.md) (ground rules 1 and 2), [deny.toml](../../deny.toml)

