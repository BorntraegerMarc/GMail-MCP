# 0010. Agent instruction files stay short and shared

- Status: Accepted (2026-11-23)
- Implementation: In place: `AGENTS.md` (the instructions), `CLAUDE.md` (imports it) and the `CLAUDE.local.md` entry in `.gitignore`. Enforced by review only.

## Context

AI coding agents will work in this repository, and a repository's instruction file is read on every task. Anthropic's guidance for Claude Code ("How Claude remembers your project" and "Best practices for Claude Code") says such a file should hold what the model cannot work out from the repo: exact check commands, places where the code misleads, decisions that are not in the code, and anything corrected twice. It should stay short, avoid emphasis and architecture overviews, and leave rules that allow no exceptions to hooks or permission rules.

A widely shared generic `CLAUDE.md` (the `multica-ai/andrej-karpathy-skills` file: think before coding, simplicity first, surgical changes, goal-driven execution) was weighed against that guidance.

## Decision

- `AGENTS.md` is the single, tool-neutral instruction file. `CLAUDE.md` contains only `@AGENTS.md` and an HTML comment that is stripped before the model sees it. Claude Code reads `CLAUDE.md` instead of `AGENTS.md` when both exist, and some sessions (older versions, notably on Amazon Bedrock before v2.1.281) read `CLAUDE.md` only, so the import keeps one source of truth.
- `AGENTS.md` holds only what the code cannot show: the exact check commands, the project's never and ask-first rules, scope, the comment convention, the decision-record rule and gotchas. It has no architecture overview, file listing or dependency list, uses plain wording without capitalized emphasis, and stays well under 200 lines.
- Rejected: the generic four-rule file. It was written for earlier models. Its "ask when uncertain" rule works against current models, which already check in too often; "simplicity first" and "surgical changes" fit in two sentences under Scope; "goal-driven execution" is stated better as the exact commands under Check your work.
- A rule that must hold without exceptions moves to a hook or a permission rule if repeating it in prose is not enough. None is needed yet.
- Personal preferences go in an untracked `CLAUDE.local.md`.

## Consequences

- One file to maintain, loaded every session. A short file is followed better than a long one, but it grows by accretion unless each addition passes the test "can the model work this out from the repo?".
- The import means sessions that cannot read `AGENTS.md` still get the same instructions, at the cost of a second file.
- Most modules do not exist yet, so the file names them by role; stale or missing references are the likeliest defect as code lands. Claude Code's `/doctor prompt-audit` (version 2.1.283 or later) is meant to catch them; not tried here.
- The wording is tuned for the Claude 5.5 models as of 2026-11-23; later models may need less.

## What would change this decision

- Anthropic's guidance changing.
- Claude Code reading both file types reliably in every session we care about, which would let `CLAUDE.md` go.
- A rule that is repeatedly ignored despite plain wording, which belongs in a hook.

## References

- [AGENTS.md](../../AGENTS.md), [CLAUDE.md](../../CLAUDE.md), [CONTRIBUTING.md](../../CONTRIBUTING.md)
- Anthropic: <https://code.claude.com/docs/en/memory>, <https://code.claude.com/docs/en/best-practices>
