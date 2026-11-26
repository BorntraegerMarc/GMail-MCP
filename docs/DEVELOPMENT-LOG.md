# Development log

How the project was built so far (2026-11-21 to 2026-11-25): what each phase delivered, how it was checked, what the reviews found, and what to avoid next time. Decisions and their reasons are in [decisions/](decisions/README.md), user-visible changes in [CHANGELOG.md](../CHANGELOG.md), what is left in [ROADMAP.md](ROADMAP.md). This file keeps the story and the lessons that none of those hold. When a phase lands, add its section and move its open items to the roadmap.

## How the work is organised

- One pull request per phase, each branch cut from `main` and squash-merged by the maintainer: `chore/scaffold` (#1), `feat/policy-core` (#3), `feat/auth` (phase 2, #4). Dependabot proposed the toolchain bump (#2).
- An AI coding assistant wrote the code and the documents under the maintainer's review. `AGENTS.md` and the decision records exist so that any session can continue from the repository alone.
- Every phase ends with the same local checks: `cargo fmt --all --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked` and, after rustdoc changes, `RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps`.
- The maintainer runs everything that touches a real account: the OAuth sign-in, the Keychain tests and the GitHub settings. Tests use synthetic fixtures and fake servers.

## Timeline

Times are CET and come from the commit history.

| When | What | Reference |
|---|---|---|
| 2026-11-21 | First brief: a small, auditable, local-only Gmail MCP server, specified as a Python program that could also create drafts. Threat model: supply chain, credential theft, prompt injection through email, silent exfiltration by the server itself | |
| 2026-11-23 | Planning session. The project became an open-source Rust crate in this repository, with a dependency policy, an egress allowlist, a CI and release pipeline and a phase plan (0 to 4). Initial commit 09:32 | |
| 2026-11-23 | Phase 0 (scaffold) and 0b (agent instructions, decision records 0001 to 0012). The first CI run needed one fix: zizmor requires a 7-day Dependabot cooldown in all three update blocks | PR #1, `b8923a0` (15:55) |
| 2026-11-23 | Dependabot raised the pinned toolchain from 1.99.0 to 1.100.0 | PR #2, `42b0aae` (16:08) |
| 2026-11-24 | Phase 1 (policy core). The first commit (10:14) still had an optional draft builder; by 11:07 the design had become read-only (see phase 1) | PR #3, `13eb58e` (12:58) |
| 2026-11-24 | Phase 2 (sign-in and credential store): feature commit 14:11, hardening after an independent review 14:59, last review findings 15:41. Pushed to `feat/auth` | `4b9b7a4` to `1caede0` |
| 2026-11-25 | Pause after phase 2; this log and the roadmap written so work can resume from the repository alone. The same day the plan was cut into a cheap beta v1 (chunks 0 to 3 in the roadmap) with a plan-first, green-light protocol for each session | |

## Phase 0 and 0b: scaffold, agent instructions, decision records

Delivered: a stub crate so CI could be green; the workflows `ci.yml`, `security.yml`, `scorecard.yml` and `release.yml`; Dependabot; `deny.toml`; the toolchain files; the README pitch, SECURITY.md, CONTRIBUTING.md, CHANGELOG, issue forms and a pull request template; `AGENTS.md` with `CLAUDE.md` importing it; decision records 0001 to 0012.

Worth remembering:

- Every GitHub Action is pinned to a full commit SHA with the version in a comment, and only four third-party actions are used (the cache, `cargo-deny`, `zizmor` and Scorecard actions). The maintainer set the repository's Actions settings to the same allowlist; that cannot be checked from the repository.
- The repository was private for a few hours on 2026-11-23 and then made public again. The jobs that need a public repository (dependency review, CodeQL, Scorecard, release attestation) carry a `github.event.repository.private == false` condition (ADR 0011).
- All CI runs on Linux; a platform-specific part gets its own narrow job (ADR 0012). The first plan had a macOS test matrix; it was dropped in the scaffold PR.
- `AGENTS.md` stays short on purpose (ADR 0010): rules an agent cannot work out from the code, and pointers.

## Phase 1: policy core

Delivered: `policy` (the scope, the route table, id validation, every limit), `http` (the egress guard), `text` (the sanitiser, the per-call nonce wrapper with one shared budget, a hand-written HTML-to-text converter), `log` (stderr, static messages). Tests: an allowlist table with hostile requests, source scans, a direct-dependency allowlist, transport tests against a local server, a proxy-environment test and property tests on untrusted input. Direct dependencies: `ureq` 3.5.2 and `oauth2` 5.0.0 (default features off), and `proptest` for tests; 82 crates in the normal tree.

Three design changes happened inside the phase, all on the morning of 2026-11-24:

- **Read-only (ADR 0014, supersedes 0002).** The optional `create_draft` tool, the `gmail.compose` scope, the `lettre` crate and the `--allow-drafts` flag were removed: that scope can send, and a mail library plus an injection surface would only save the user a copy and paste. The assistant writes a suggested reply into a Markdown file instead.
- **Hand-written HTML converter instead of `html2text` (ADR 0013).** Alternatives were tested and are recorded in the ADR. The converter's cost follows the input length and it cannot panic.
- **Constrained queries.** The route table passes only listed query parameters and values, so a tool argument cannot smuggle in another request shape.

## Phase 2: sign-in and credential store

Delivered: `gmail-mcp auth [--credentials <client_secret.json>]` (OAuth authorization code with PKCE and a random `state`, a loopback listener on 127.0.0.1, a consent address that the user opens by hand because no code starts a process); the scope rule (`policy::check_grant`: exactly `gmail.readonly`, anything else or nothing reported is refused before anything is stored, and an existing item is left as it was); one Keychain item holding the credentials (`security-framework`, macOS only; a stub that fails closed elsewhere); `scripts/verify-no-plaintext-secrets.sh`; `--version`; a narrow `macos-store` CI job behind a `changes` job; ADR 0015 and updates to ADRs 0003, 0004, 0006, 0007, 0009, 0012 and 0014. New dependencies: `serde_json` (already in the tree) and, on macOS, `security-framework` (5 more crates; 87 on macOS, 82 on Linux, all MIT or Apache-2.0).

How it was checked:

1. Tests against fakes and real loopback sockets: the whole sign-in against a fake Google and a fake store, the listener with stray, silent, slow, oversized and repeated requests, the scope rule with look-alike scopes and doctored store records, the binary's exit codes, the script on synthetic files.
2. Four rounds of hand-made mutation testing, about 50 deliberate breakages of guards (invert a comparison, widen an allowlist, drop a check). Each must turn a test red; a mutation that stayed green became a new test. Verify that a mutation really applied: a rustfmt reflow made some text replacements fail silently and gave false "not caught" results.
3. A simulated-Linux run for the macOS-only code (see the pitfalls).
4. An independent reviewer on the diff, then a large fan-out review (eight areas, 171 agents): 54 findings, and every blocker and important one was fixed or documented.

Real defects the checks found, as a checklist for later phases:

- `ci.yml` was invalid YAML (an unquoted `store::` in a `run` step), so no job would have started. `tests/ci_workflow.rs` now guards that and checks that `ci-success` lists every job.
- A silent connection could starve the loopback listener. It is now a non-blocking multiplexer: 5 seconds per connection, at most 16 connections, the oldest pushed out.
- A header cap of 8 KiB rejected genuine redirects that carried cookies stored for 127.0.0.1. Only the first request line counts now.
- The reply page said "Signed in" before the code exchange and the scope check had run. It no longer claims that.
- The consent-address logger could print arbitrary query text. It now allows listed parameters only and never a fragment.
- The secrets script reported "Nothing found" after failing to look: a symlinked root, an unreadable folder, a mistyped folder name, a root called `target`, a different locale, missing tools. It now exits 2 when it could not look.
- The source scan's comment stripper missed raw byte strings, DNS-lookup calls were not scanned, `deps_policy` read only the manifest (it now asks `cargo metadata`), and the `changes` job echoed file names that could start a workflow command (the list is indented).
- Refusal messages gave no advice (they now say to remove the app's access in the Google account and sign in again); there was no `--version` although the bug template asks for it.
- macOS: sockets accepted from a non-blocking listener inherit non-blocking mode (verified by a mutation).

Measured facts (2026-11-24): Google's device flow does not allow Gmail scopes (ADR 0015); a plain unauthenticated request to both Google hosts completed the TLS handshake with the egress settings and returned 404 on the root paths.

State at the hand-off: fmt, clippy (macOS and simulated Linux), rustdoc and the tests were green locally, and the repository was free of plaintext-secret patterns and personal data. Not verified: any CI run, the Keychain on a real machine, the live Google flow.

## Phase 3a: Gmail core (chunk 1 of the beta)

Delivered: `gmail` (the client over a one-method `Transport`; labels, thread search with one metadata read per hit, thread and message with `format=full`; a MIME walk bounded to depth 8, 200 parts and 1 MiB of text; statuses mapped to static errors; one refresh and one retry after a 401), `session` (credentials read on the first token request, the refresh-token grant through `oauth2` over `auth::Guarded`, `policy::check_grant` on every token response) and `tools` (the four read tools as plain functions, every mail-derived string through `text::Untrusted`). One new direct dependency, `base64` pinned to 0.22.1, which the tree already held. 27 new tests in `tests/gmail_tools.rs` and `tests/session_refresh.rs`, all with synthetic hostile mail and fakes; nothing was run against Google.

How it was checked: fmt, clippy `--all-targets`, rustdoc and the full suite, then eight deliberate breakages of the new guards (the 401 retry, the MIME depth, the part count, the query encoding, the grant check, the store re-read, the per-message share of the budget, a header left unwrapped); each turned a test red. There was no reviewer. The one thing the checks found was the scope scan tripping on a field name (see the pitfalls).

## Decisions of 2026-11-25 (planning the beta)

- **A cheap beta first.** The remaining work is cut into chunks (land phase 2; Gmail core; MCP server; live test) with a budget of about $14 in model spend (range $10 to $19) instead of one large phase 3 and phase 4. Everything polished moves to the roadmap's "After the beta" and backlog.
- **`rmcp` stays.** A hand-written protocol layer was weighed: about 300 lines on `serde_json`, no tokio, no new crates (the tree would stay at 82), but it needs a new decision record and one exception in the print scan (`stdout` is banned in all of `src/`). The maintainer chose the official SDK as planned, knowing it adds tokio and about 72 crates and likely costs $5 to $8 for that chunk.
- **No `config` subcommand.** The Claude Desktop JSON block is printed by a paste-and-run shell command in the README: printing a dynamic path from the binary would need another exception in the print scan.
- **Working protocol.** A session that is asked to continue first presents a plan for a whole chunk and waits for the maintainer's go-ahead; it then works lean and stops after the chunk.
- **Third-party Claude Desktop.** The maintainer's `claude_desktop_config.json` has no `mcpServers` entry (key names only were read, 2026-11-25), so where this deployment reads local MCP servers from is open until the live test.

## Pitfalls met so far

Static scans (`tests/static_policy.rs`):

- They read all of `src/`, `#[cfg(test)]` modules included, with comments removed (raw and byte strings handled). Keep these out of `src/`: process APIs such as `Command`, `stdout` or `stderr` outside `log.rs`, `.delete(` and `.put(`, plain `http://` literals (build them from parts in tests), `std::net`, `TcpListener` and `TcpStream` outside the two files that may use them, `connect(`, a second `bind(`, `cfg_attr`. Hostile samples belong in `tests/`, described by a comment in `src/`. The store's removal method is called `remove` for this reason.
- A new direct dependency fails `tests/deps_policy.rs` until its allowlist is updated (macOS-only crates go in `MACOS_TABLE`). The test asks `cargo metadata`, so renamed, target-specific and build dependencies are caught too.
- The token `stdout` is banned in all of `src/` (and `stderr` outside `log.rs`), so protocol output has to come from a dependency's transport. URL literals are allowed only for `https` and the two Google hosts (the consent page only in `policy.rs`); a URL assembled with `format!` is not seen by that scan.
- The scope scan reads the fragments `gmail.labels` and `gmail.metadata` anywhere in code, so a field called `gmail` with a method `labels` (`self.gmail.labels()`) fails it. Name such a field `client`.

CI:

- Quote any `run:` value that contains a colon followed by a space. Every new job joins `ci-success.needs` (a skipped job counts as passed). Never echo file names or other outside text unindented in a `run` step: a line that starts with `::` is a workflow command.
- `macos-store` is enabled by a Linux job (`changes`) that diffs the pull request; runs on `main` and manual runs always include it.
- CodeQL for Rust reports "Cleartext logging of sensitive information" (high severity) when an assert message interpolates text derived from a secret-named value, for example `assert!(!shown.contains("..."), "{shown}")` where `shown` is the debug output of a secret type. It does so in test code too, and the "CodeQL" results check then fails the pull request (five alerts on the first run of phase 2). Use static assert messages for anything derived from a token or secret; a label such as `("client secret", value)` keeps a failing case identifiable.

Clippy (pedantic, with `unwrap`, `expect`, print macros and `dbg!` denied) cost iterations on: `needless_pass_by_value`, `unnecessary_wraps` (an item-level `allow` with a reason is fine in a test helper), `semicolon_if_nothing_returned`, unchecked `Duration` subtraction (use `saturating_sub`), file-extension comparison (use `Path::extension` with `eq_ignore_ascii_case`) and asserts without a message. Run clippy with `--all-targets`.

Platform split:

- The maintainer's Mac cannot run the Linux paths. To check them, copy the tree to a scratch folder, change `target_os = "macos"` to `target_os = "none"` in `src/store.rs`, `tests/keychain_macos.rs`, `tests/store_policy.rs` and `tests/cli_binary.rs`, point `CARGO_TARGET_DIR` at a scratch location, run fmt, clippy and tests there, then delete everything. Scratch copies with their own `target/` reached tens of gigabytes.
- The MSRV job runs on Linux and does not compile macOS-only code.

Libraries and platforms:

- `oauth2` is used with no HTTP-client feature: `auth::Guarded` implements its `SyncHttpClient` trait over the egress guard, and client credentials go in the request body. The crate's parse errors hold the response body, which can hold tokens, so errors keep only a kind.
- An OAuth consent screen in "Testing" status issues refresh tokens that expire after 7 days.
- A rebuilt, ad-hoc signed binary may make macOS ask for Keychain access again.

Tooling:

- `gh`, the 1.89 toolchain, `cargo-deny` and `zizmor` are not installed on the maintainer's machine. Reading pull requests and CI goes through the GitHub MCP tools, where list calls that return arrays have failed and number-based reads work.
- After `cargo fmt` or a script has touched a file, re-read it before editing: the editing tools refuse a file that changed since it was read.

Process:

- Several real defects came from running what CI would run before pushing (fmt, clippy, tests, a YAML parse, the simulated-Linux run), which costs almost nothing.
- Review paid most when pointed at the security claims and at the CI and test infrastructure: several real defects were in the workflow, the scans and the script rather than in product code. A claim in a document is a thing to test; reviews flagged several overclaims.
- The fan-out review found real issues but cost several times what the implementation did. For phase 3 use one targeted reviewer (see the roadmap).
