# 0002. Two-layer permission model, read-only by default

- Status: Accepted (2026-11-23)
- Implementation: Not implemented as of 2026-11-23: only the project scaffold exists, with no server code. Planned: the scope request, grant storage and the refusal rule in `auth` (phase 2); the tool-list switch and the clear `create_draft` failure in `serve`, and a stdio smoke test that asserts both tool lists exactly (four tools by default, five with `--allow-drafts`) (phase 3). CHANGELOG.md records what has landed since.

## Context

Email is attacker-controlled input, and an assistant that reads it can be steered by it (prompt injection; see "Security design at a glance" in README.md). The worst case through this server must be a draft that the user sees before anything is sent.

Google has no draft-only scope. Drafts here use `gmail.compose`, which technically permits sending at the API level. The first design exposed all five tools and always requested `gmail.compose`. The maintainer then required that the grant can be scoped to read-only, which produced this model. Google's consent screen also lets users untick individual scopes, so a grant can be narrower than the request.

## Decision

Permissions come in two independent layers, and the default is read-only. Drafts need an explicit opt-in in both, so either layer alone blocks them.

- **Layer 1, Google-side scope (enforced by Google).** By default `gmail-mcp auth` will request only `gmail.readonly`. `gmail-mcp auth --allow-drafts` will request `gmail.readonly` plus `gmail.compose`.
- **Layer 2, server-side tool list.** `gmail-mcp serve` will expose four read tools: `list_labels`, `search_threads`, `get_thread`, `get_message`. `gmail-mcp serve --allow-drafts` will add `create_draft`.
- **No other write tools.** Send, forward, reply-send, delete, trash, untrash, spam, label create/modify/apply, filters and settings are not implemented and will not be added.
- **Granted scopes are read from the token response**, not taken from the request. `auth` will store them and refuse to store a grant without `gmail.readonly`, which both modes request.
- **Replaced: `gmail.compose` always on.** Every user would be asked for a scope that can send at the API level, including users who never want drafts.

## Consequences

- With a read-only grant, creating a draft is impossible even if the tool code or the Gmail client had a bug, because Google enforces the scope. That holds only if the grant really is read-only, so `auth` prints what Google actually granted for the user to check.
- Upgrading from read-only to drafts will take two steps: re-run `gmail-mcp auth --allow-drafts`, then start `serve` with `--allow-drafts`. The stored grant and the `serve` flag have to be kept consistent: `gmail.compose` without the flag leaves `create_draft` unlisted, and the flag without `gmail.compose` must make `create_draft` fail with a clear message.
- In drafts mode the no-send guarantee is weaker than in read-only mode, because `gmail.compose` allows sending at the API level. It rests on the code never calling a send endpoint, and on the egress allowlist and the static tests (both planned for phase 1, see 0003-single-egress-allowlist.md).
- The planned smoke test is the mechanical guard for layer 2: adding a tool changes the asserted list, so it shows up in review instead of passing silently.
- The layers bound what this server can do, not what the assistant does with its other tools (see 0005-untrusted-email-content.md).
- Costs: two modes to build, test and document, and `auth` has to cope with grants narrower than requested.

## What would change this decision

- Google offering a scope that can create drafts but not send. Drafts mode could then rest on Google's enforcement the way read-only mode does.
- A measured need for more tools, not a guess that someone might want them. The actions under "No other write tools" stay out regardless.

## References

- [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md): the egress allowlist that backs the no-send guarantee in drafts mode.
- [0005-untrusted-email-content.md](0005-untrusted-email-content.md): prompt injection through email and the limits of wrapping.
- [0006-credentials-in-macos-keychain.md](0006-credentials-in-macos-keychain.md): the Keychain item that holds the granted scopes.
- [README.md](../../README.md): "Security design at a glance", "Two layers of permission" and "Honest limits".
- [CONTRIBUTING.md](../../CONTRIBUTING.md): ground rules on write capability and on changing what the server can do.
- [SECURITY.md](../../SECURITY.md): any way to make the server send or change settings is in scope for vulnerability reports.

