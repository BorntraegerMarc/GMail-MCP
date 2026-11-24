# 0014. The server only reads mail; suggested replies are written by the assistant

- Status: Accepted (2026-11-24); supersedes [0002](0002-two-layer-permission-model.md)
- Implementation: Partly in place (phase 1). The route table has no Gmail route but `GET`, the only scope the code names is `gmail.readonly`, and no mail library is in the tree; `src/policy.rs` and its unit tests, `tests/egress_policy.rs`, `tests/static_policy.rs` and `deny.toml` pin all three. Planned: `auth` requests only `gmail.readonly` and refuses to store a grant that holds any other scope (phase 2); `serve` lists exactly the four read tools, has no mode flag, and a stdio smoke test asserts the list (phase 3); the README and SETUP.md describe how to get a suggested reply (phase 4).

## Context

The first design (0002) had five tools: four reads and `create_draft`, which needed the `gmail.compose` scope and a `--allow-drafts` flag. Google has no draft-only scope, and `gmail.compose` permits sending at the API level, so in drafts mode "nothing is sent" rested on this project's code, its egress allowlist and its tests, and not on Google. Drafts were also where most of the custom security code sat: checks against header injection, address parsing, a mail library and its dependencies, and text the user could not see in a draft the user was meant to read.

On 2026-11-24 the maintainer decided that the server need not compose mail at all. It never sent anything; its one write was a draft. A suggested reply works better as a Markdown file that the assistant writes and the user copies into their mail client.

## Decision

- The server reads mail and does nothing else. It has four tools: `list_labels`, `search_threads`, `get_thread` and `get_message`. None writes to Gmail and none writes to disk.
- It requests one OAuth scope, `gmail.readonly`, and the code names no other. Google enforces it: a token that holds only this scope cannot send, create a draft, or change or delete anything, whatever this code or one of its dependencies does. `auth` refuses to store a grant that holds any other scope.
- The egress guard and its route table stay (0003). The Gmail host has no route but `GET`. The guard also does the job the scope cannot: it keeps the server from contacting any other host.
- The server composes no mail: no mail library, no `gmail.compose`, no drafts endpoint. The route-table test, the source scan and `deny.toml` (which bans `lettre`) enforce it.
- Replies: the user asks the assistant for a suggested reply, the assistant writes it to a Markdown file with its own file tools in a folder the user chooses, and the user reads it and pastes it into their mail client. The server takes no part in writing the file.
- Rejected: keeping `create_draft` behind `--allow-drafts`. It needs the scope that can send, a mail library and an injection surface, to save the user a copy and paste.
- Rejected: a server tool that writes the Markdown file. It would add file-system writes and path handling to a server that otherwise touches no files, and the assistant already has file tools.

## Consequences

- The no-write guarantee is now Google's, and no longer depends on this code being right. The route table, the source scan and the tests stay as defense in depth, and the guard's other job (no other host) is unchanged.
- The design gets smaller: no mode flag, one tool list, no input validation for composing, and `lettre` with its dependencies is out of the tree.
- The worst case through this server is now "it reads mail it was asked for": it cannot send, draft, change or delete anything. A model steered by a hostile email can still misuse its other tools, for example by writing a misleading suggested reply to a file or fetching a URL, and this server cannot prevent that (0005). The user reads a suggested reply before pasting it.
- Costs: there are no one-click drafts in Gmail and no automatic threading; the user replies in their own client. `gmail.readonly` still reaches all mail, and `gmail.metadata`, which cannot read bodies, does not fit the use.
- Phase 2 has to check the grant: an earlier consent for the same OAuth client could hand back more scopes than the request names, so `auth` compares what Google granted with the one scope it wants and refuses anything else.

## What would change this decision

- Google offering a scope that creates drafts but cannot send. Drafts could then rest on Google's enforcement; it would still need its own record, scope, route and tests.
- Sending, forwarding and deleting stay out regardless (`CONTRIBUTING.md`, rule 1).

## References

- Decision records: [0002-two-layer-permission-model.md](0002-two-layer-permission-model.md) (superseded), [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md), [0005-untrusted-email-content.md](0005-untrusted-email-content.md), [0006-credentials-in-os-credential-store.md](0006-credentials-in-os-credential-store.md)
- Repo files: [README.md](../../README.md), [CONTRIBUTING.md](../../CONTRIBUTING.md), [deny.toml](../../deny.toml), [src/policy.rs](../../src/policy.rs)
