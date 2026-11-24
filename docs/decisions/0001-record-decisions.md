# 0001. Record decisions

- Status: Accepted (2026-11-23)
- Implementation: In place: `docs/decisions/` (index and template), `AGENTS.md` (`CLAUDE.md` imports it), the "Comments and decisions" section of `CONTRIBUTING.md` and two pull request template checkboxes. Enforced by review only.

## Context

- The design was settled before any server code existed. Its detailed reasoning (why read-only by default, why one egress guard, why these crates, which alternatives were rejected) lived only in a private planning document outside this repository. Rationale that lives in a chat log or a private plan is lost to whoever reads the repository later.
- The design calls for guards that are redundant on purpose, for example an egress allowlist (`0003-single-egress-allowlist.md`) on top of a read-only OAuth scope. They look removable to a reader, human or AI, who sees only what the code does and not why.
- A comment lives in one file, but a decision such as the permission model (`0014-read-only-no-composing.md`) spans several.

## Decision

- Design decisions are recorded as short architecture decision records (ADRs) in `docs/decisions/`: one page and one file each, numbered, never deleted. `docs/decisions/README.md` holds the index and the template.
- A comment carries the local why of a guard, limit or allowlist entry and may link its record; a record carries the design decision behind it.
- Whoever changes a decision adds a new record or supersedes the old one in the same pull request. A superseded record stays in place with the status Superseded, so links to it keep working.
- `AGENTS.md`, `CONTRIBUTING.md` and the pull request template state this rule.
- Alternatives rejected: rationale only in code comments, which cannot hold a decision that spans several files; and rationale only in a private plan outside the repository, which only the maintainer can read and which cannot be reviewed with the change.

## Consequences

- Benefit: A decision's reasons live in the repository, where they can be reviewed with the change.
- Cost: Every design change carries one record, a small overhead, and authors must judge whether a reason is local (a comment) or a design decision (a record).
- Cost: Records can go stale. The pull request checklist and the Superseded status limit this, but both come into play only when someone makes or changes a decision. The Implementation line is the most likely to go stale: nothing prompts an update when the phase that implements a record lands.
- Cost: Nothing checks the rule mechanically. The checklist is self-attested, and with one maintainer the author of a change is usually also its reviewer.
- Limit: A record explains a guard but does not stop anyone from removing it. It makes removal by mistake less likely; the author and reviewer still have to catch the rest.

## What would change this decision

If records are not maintained (for example, design changes merge with the checklist item ticked and no record added or superseded), replace them with something lighter, by superseding this record.

## References

- [0014-read-only-no-composing.md](0014-read-only-no-composing.md)
- [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md)
- [CONTRIBUTING.md](../../CONTRIBUTING.md)
- [.github/PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md)

