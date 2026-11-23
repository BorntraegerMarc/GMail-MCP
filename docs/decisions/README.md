# Decision records

Each design decision is recorded here as a short architecture decision record (ADR), one file per decision, saying what we decided and why. The ground rules and comment conventions are in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Why we keep them

The code shows how something works, not why. Several guards in this design are deliberately redundant, so each looks removable to someone who sees only the how. For example, record [0003](0003-single-egress-allowlist.md) limits egress to an allowlist even though the OAuth scopes in [0002](0002-two-layer-permission-model.md) already narrow what the token can do. The allowlist is not a duplicate: `gmail.compose` itself permits sending, so with drafts enabled the guarantee that nothing is sent rests on the code, the allowlist and its tests, not on the scope. A record keeps such a reason in the repo and can hold a decision that spans several files, which a code comment cannot; the guard then points to it with a comment such as `// why: docs/decisions/0003-single-egress-allowlist.md`.

## When to write one

Write a record when a change constrains future code, widens or narrows what the server can do or trust, picks or rejects a dependency, or reverses an earlier decision. Do not write one for how-level detail the code already shows. A record explains a decision; it does not authorize one: the ground rules still apply, so no record lifts the ban on new write capability, and a change that widens the server also needs the PR security note and the allowlist, test and README security-table updates the ground rules require.

## Template

Name the file `NNNN-short-slug.md`: the next unused number and a few lowercase, hyphenated words that name the decision (the index shows examples). Add a row to the index below. Keep a record to about one page (roughly 900 words); the two broad ones, on the dependency list (0004) and the CI pipeline (0007), run longer, and a record that grows should be split instead.

```markdown
# NNNN. Title

- Status: Accepted (YYYY-MM-DD)
- Implementation: what enforces it today (files, tests, or review only) and what is still planned, with its phase; "not applicable" if there is nothing to build

## Context
The threat or constraint, and the alternatives actually weighed (if there were none, say so; do not invent any).

## Decision
What we do and the invariant it protects, stated plainly in the present tense, even for work not yet built (the Implementation line carries the build status). Leave how-level detail to the code. Rejected alternatives may be listed here as `Rejected:` bullets with their reasons.

## Consequences
What gets easier, what gets harder, and what risk remains. Measurements and external claims are as of the Status date unless dated inline; label expectations you have not verified as unverified.

## What would change this decision
The evidence or event that should make us reopen it.

## References
Related records and external sources (Google docs, crate pages). Link only what exists.
```

## Lifecycle

Status is `Accepted`, `Superseded by NNNN`, or `Deprecated`, followed by the acceptance date as in `Accepted (YYYY-MM-DD)`; a status change keeps the date, so the record's claims stay dated. Never delete a record. To change a decision, add a new record in the same PR and mark the old one `Superseded by NNNN`; to retire one that nothing replaces, mark it `Deprecated` and give the reason in the Status line. A superseded or deprecated record is frozen except for its Status line and links.

Each index row repeats its record's Status line and reduces its Implementation line to a short state: In place, Partly in place, Planned or Not applicable, plus the phases of any work still planned. The Implementation line is authoritative and holds the detail. The PR that lands or changes the code a record describes updates that line, and the row if the state changes. Nothing checks this: if a row or an Implementation line disagrees with what the repo contains, trust the repo and correct both.

## Index

Phases are the planned build order (delete this sentence once phase 4 ships): 0 scaffold, 0b agent instructions and decision records, 1 policy core, 2 auth, 3 Gmail client and MCP tools, 4 full docs and the first release.

| Record | Title | Status | Implementation |
|---|---|---|---|
| [0001](0001-record-decisions.md) | Record decisions | Accepted (2026-11-23) | In place |
| [0002](0002-two-layer-permission-model.md) | Two-layer permission model, read-only by default | Accepted (2026-11-23) | Planned, phases 2 and 3 |
| [0003](0003-single-egress-allowlist.md) | Single egress function with an allowlist | Accepted (2026-11-23) | Planned, phases 1 and 2 |
| [0004](0004-dependency-policy-and-libraries.md) | Dependency policy and library choices | Accepted (2026-11-23) | Partly in place; the rest planned, phases 1 to 3 |
| [0005](0005-untrusted-email-content.md) | Untrusted email content handling | Accepted (2026-11-23) | Planned, phases 1 and 3 |
| [0006](0006-credentials-in-os-credential-store.md) | Credentials only in the OS credential store (macOS Keychain first), fail closed | Accepted (2026-11-23) | Planned, phases 1 to 3 |
| [0007](0007-supply-chain-posture.md) | Supply-chain posture for CI and releases | Accepted (2026-11-23) | Partly in place; the rest planned, phase 4 |
| [0008](0008-blocking-http-client.md) | Blocking HTTP client; tokio only as the MCP runtime | Accepted (2026-11-23) | Planned, phases 1 and 3 |
| [0009](0009-stdio-only-transport.md) | MCP over stdio only, no network-exposed endpoint | Accepted (2026-11-23) | Planned, phases 2 and 3 |
| [0010](0010-agent-instruction-files.md) | Agent instruction files stay short and shared | Accepted (2026-11-23) | In place |
| [0011](0011-private-for-now.md) | Private for now; public-only checks are skipped, not removed | Accepted (2026-11-23) | In place |
| [0012](0012-ci-on-linux.md) | CI runs on Linux; platform-specific code gets narrow jobs | Accepted (2026-11-23) | Partly in place; the rest planned, phase 2 |
