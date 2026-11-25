# Roadmap and resume guide

Where the build stands and what to do next, written so that a fresh session can continue from the repository alone. Update it whenever a chunk lands. The story so far, with the lessons, is in [DEVELOPMENT-LOG.md](DEVELOPMENT-LOG.md); the reasons behind the design are in [decisions/](decisions/README.md). Last updated: 2026-11-25.

## Start here: "continue the work towards v1"

The goal is a **beta v1 that the maintainer can test from Claude Desktop, for roughly $10 to $15 of model spend**: usable, not finished, not polished. The work is cut into chunks, a whole phase by default. Each chunk ends in a pushed branch and a pull request that the maintainer merges.

When asked to continue the work towards v1 (or to resume the build), do this:

1. **Orient, in at most six calls.** `git status`, `git log --oneline -5`, the current branch; whether the open pull request is merged and what its CI says (GitHub MCP, `pull_request_read`; `gh` is not installed). Find the first chunk under "Beta v1: the chunks" whose "Done when" is not met. The checkboxes are hints; the "Done when" lines are the truth.
2. **Plan first, then wait for the green light.** Tell the maintainer what this session will do: the chunk, its steps, the files it will touch, the checks, the rough budget (calls and dollars, from the table) and any decision that is theirs. Ask for the go-ahead with AskUserQuestion ("Go" and "Adjust"), or through the plan-approval step if plan mode is on. Edit nothing before the answer. A chunk is the default size; do less or more only if the maintainer says so.
3. **Work lean** (rules at the end of this file). Do not reopen "Fixed decisions for the beta". Stay inside the chunk's budget; if it will run over by half, stop and say why.
4. **Close the chunk.** Run fmt, clippy and the full tests once. Tick the chunk, add a line to the progress log, move every shortcut and follow-up to the backlog, commit with the `Co-Authored-By` trailer and push the feature branch. Never push to `main`, never merge, and open a pull request only when asked.
5. **Report in at most ten lines:** what was built, each check's result, what the maintainer must do next (name the exact step) and which chunk comes after. Then stop.

If the next step is the maintainer's (merge, sign-in, live test), say so and stop; do not start the following chunk.

## State at a glance

| Phase | Scope | State |
|---|---|---|
| 0, 0b | Scaffold, CI and security tooling, agent instructions, decision records | Merged: #1 (`b8923a0`), toolchain bump #2 (`42b0aae`) |
| 1 | Policy core: the one scope, the egress guard, untrusted-content handling | Merged: #3 (`13eb58e`) |
| 2 | Sign-in: `gmail-mcp auth`, the Keychain store, the scope refusal | Finished on branch `feat/auth` (last code commit `1caede0`, then docs). Its pull request is chunk 0 below; CI has never run on it |
| 3 | Gmail client, the four read tools, the MCP server | Not started. Split in two for the beta: 3a Gmail core (chunk 1) and 3b MCP server (chunk 2) |
| 4 | Full README, SETUP.md, AUDIT.md, first release | After the beta, see "After the beta: v1.0" |

**Works today** (by tests; never yet against Google): `gmail-mcp auth [--credentials <client_secret.json>]` runs the sign-in and stores read-only credentials in the macOS Keychain. Other platforms fail closed and never fall back to a file.

**Does not exist yet:** any Gmail call, any tool, any MCP server. `gmail-mcp serve` says it is not implemented and exits with code 2, so nothing can be used from Claude until chunk 2 lands.

Size at the end of phase 2: about 4,300 lines in `src/` (a good part is unit tests), about 200 tests (4 `#[ignore]`d), 82 crates in the Linux dependency tree and 87 on macOS, 15 decision records.

**Never exercised yet:** every CI job on the phase 2 branch (the MSRV job does not compile the macOS-only code at all; the 1.89 toolchain, `cargo-deny` and `zizmor` are not installed on the maintainer's machine, so CI is where they run first); `gmail-mcp auth` against Google; the Keychain code on a real keychain (its tests are `#[ignore]`d, CI runs them on a throwaway keychain); `release.yml`, not even as a dry run.

## Beta v1: the chunks

Budget is model spend at Bedrock global Sonnet 5.5 prices in lean sessions, plus or minus half. The total is about $14 (range $10 to $19): the $10 target holds only if `rmcp` goes smoothly and CI and the live test need no fixes. "Calls" is a cap on tool calls: an agent can count them, but it cannot see the bill.

| Chunk | Scope | Plan | Calls |
|---|---|---|---|
| 0 | Land phase 2: read the first CI run, fix what it shows, the maintainer merges | $1 | 15 |
| 1 | Phase 3a, Gmail core: Gmail client, token refresh, the four tools as plain functions, tests against fakes | $4.50 | 70 |
| 2 | Phase 3b, MCP server: `rmcp`, `serve`, smoke test, quick start, docs batch | $6 | 70 |
| 3 | Beta test: the maintainer's live run, then one fix session | $2 | 30 |

### Chunk 0: land phase 2

- [ ] The pull request from `feat/auth` is merged into `main` and `ci-success` is green on `main`.

The pull request from `feat/auth` was opened on 2026-11-25; the maintainer merges it when `ci-success` is green. An agent session reads the CI result and fixes what is red on the same branch. The first run of `cargo-deny`, `zizmor`, the 1.89 MSRV build and the macOS job `macos-store` is where surprises are most likely. Never weaken a check to get green; if a failure needs more than about 15 calls, stop and report. Done when: `git log origin/main` shows the phase 2 commit and CI on `main` is green.

### Chunk 1: phase 3a, Gmail core (branch `feat/gmail-core`, from `main`)

- [ ] `Tools` with its four methods exists, is tested against fakes, and `cargo test --locked` is green on the pushed branch. `serve` is still the stub.

Read first, and only this: the route table and limits in `src/policy.rs`, `text::Untrusted`, `auth::Guarded` and `auth::login`, `store::{CredentialStore, Credentials}`, and the helpers in `tests/auth_flow.rs`.

1. **`src/gmail.rs`.** A `Transport` trait with one method (GET a path with the bearer token, return status and bytes); the production implementation sits on `http::Egress`, tests use a fake. Calls: labels; threads list (`q`, `maxResults`); a metadata read per hit (`format=metadata`, `metadataHeaders` Subject, From and Date); thread and message with `format=full`. All of these are already in the route table, so `policy.rs` does not change. Parse with `serde_json::Value`, use `get` and never index, never panic. Decode base64url with the `base64` crate that ADR 0004 plans and that is already in the tree: pin the version `oauth2` uses (`cargo tree -i base64`; a duplicate version only warns in `deny.toml`), padding optional. Walk the MIME parts with a depth limit (8) and a part limit (200). Prefer `text/plain`; HTML-only goes through `text::html_to_text`; attachments are filename, type and size only. Map the HTTP status to static error variants (401 leads to one refresh and one retry; 403 says "refused: is the Gmail API enabled and `gmail.readonly` granted?"; 404; 429; anything else). No Google response body in any message.
2. **`src/session.rs`.** Credentials load lazily from `store::platform()` on first use. The refresh-token grant goes through the `oauth2` crate over `auth::Guarded` (copy how `auth::login` builds the client). Every token response passes `policy::check_grant`, and a response without a `scope` field fails closed (note it in the backlog: a live check shows whether Google omits it). The access token and its expiry stay in memory. Static messages: no credentials means "run `gmail-mcp auth`"; `invalid_grant` means "Google no longer accepts the stored sign-in; run `gmail-mcp auth` again (a consent screen in Testing status expires after 7 days)".
3. **`src/tools.rs`.** `Tools` with `list_labels`, `search_threads(query, max_results)`, `get_thread(id)` and `get_message(id)`. Each validates its arguments (`ResourceId::parse`; `max_results` 1 to 25, default 10; a bound on the query length), calls Gmail, and returns one `String` built only through `text::Untrusted` (the `notice()` line first, every email-derived field through `wrap` or `wrap_body`, label names included), or a static `ToolError`. When `Untrusted::exhausted()` is true, stop and say so outside the delimiters.
4. **Tests, only these.** Synthetic hostile fixtures through the fake transport (look-alike delimiters, invisible characters, an id containing `../`, deep MIME nesting, bad base64, missing fields); a fake token endpoint for the refresh path; one test that no raw hostile string appears outside a wrapper in any tool's output.
5. Close the chunk (protocol step 4), branch `feat/gmail-core`. The pull request title: "feat: Gmail client, token refresh and tool output (phase 3a)".

### Chunk 2: phase 3b, the MCP server (branch `feat/mcp-server`, from `main`)

- [ ] `gmail-mcp serve` answers `initialize` and `tools/list` with exactly the four tools in `tests/stdio_smoke.rs`, the checks are green, and the README has the quick start.

Read first, and only this: the `rmcp` crate's README and `examples/` in the cargo registry source (after the spike adds it), `src/main.rs`, `Task::Serve` in `src/cli.rs`, the spawn pattern in `tests/cli_binary.rs`, and the scans you must not trip in `tests/static_policy.rs`.

1. **Dependency spike, with a stop gate.** Add `rmcp` with `default-features = false` and the features ADR 0004 names (`server`, `macros`, `transport-io`; check the names against the crate), `tokio` (`rt`, `macros` and whatever the stdio transport needs), and `serde` or `schemars` only if the tool macros require them as direct dependencies. Exact `=` pins. Start from the smallest stdio example in the crate and make it compile before adding tools. Then report to the maintainer: the crate count from `cargo tree` (ADR 0008 measured 72 more crates for `rmcp` plus tokio on 2026-11-23, so about 140 in total), the MSRV of the tree (the floor is 1.89; if anything needs more, stop and ask, it is the maintainer's call) and the licences (`cargo-deny` is not installed: read the licence fields from `cargo metadata`). Update `tests/deps_policy.rs` and the comments in `Cargo.toml`. If the spike takes more than about 15 calls or the tree is far beyond 150 crates, stop and tell the maintainer.
2. **`src/server.rs` and `serve`.** The `rmcp` handler with the four tools and read-only annotations, each calling `Tools` inside `spawn_blocking` on a tokio current-thread runtime; a result is one text content, a failure is a tool error with the static text. Replace the stub in `src/main.rs`; exit codes stay as they are. Nothing may print to stdout: the scan bans the token `stdout` anywhere in `src/`, so `rmcp`'s transport does the writing.
3. **`tests/stdio_smoke.rs`.** Spawn the built binary: `initialize`, then `tools/list` returns exactly the four names; a `tools/call` without credentials gives a tool error that names `gmail-mcp auth`; end of input ends the process cleanly. It must not touch the Keychain (the lazy load makes that so).
4. **Scans and policy tests.** tokio and `rmcp` only in `src/server.rs` and `src/main.rs`; no `tokio::net` and no `tokio::process`; every other scan stays. Each change to a scan gets a comment saying why (ADR 0008, 0009).
5. **Docs batch.** README: status "Beta", what works, the quick start, the honest beta limits. The quick start has a paste-and-run command that prints the Claude Desktop JSON block with the absolute path of the built binary (`printf` with `$(pwd)`; no new subcommand, because printing a dynamic string would need another exception in the print scan), and a check without Claude: pipe the `initialize` and `tools/list` lines into `gmail-mcp serve`. CHANGELOG. Implementation lines and index rows of ADRs 0004, 0005, 0006, 0008, 0009 and 0014. Add `src/gmail.rs`, `src/session.rs` and `src/server.rs` to the security-critical files in CONTRIBUTING.md.
6. **Self-check before closing,** by grepping the diff: indexing or slicing of untrusted data, `unwrap` and `expect`, recursion without a depth limit, any email-derived string that skips `Untrusted`, any format of data into a log message.
7. Close the chunk, branch `feat/mcp-server`. The pull request title: "feat: MCP server with the four read tools (phase 3b)". Its body needs the PR security note: the new dependencies with the crate count, no new host, method or scope.

### Chunk 3: beta test (the maintainer, then one agent session)

- [ ] The maintainer has listed labels, searched and read a thread and a message through Claude Desktop, and says the beta is usable.

Maintainer steps:

1. Sign in if you have not (below). Merge the chunk 2 pull request when `ci-success` is green, then `cargo build --release --locked`.
2. Run the check without Claude from the README quick start: it prints the four tool names.
3. Add the server to Claude Desktop with the JSON block the README command prints, and restart the app. Where the third-party (Bedrock) deployment reads local MCP servers from is unverified: when last looked at (key names only, 2026-11-25), its `claude_desktop_config.json` had no `mcpServers` entry. Find out first (the app's Developer settings or its third-party configuration) and write the answer here.
4. Ask Claude to list your labels, to search (for example `newer_than:7d`), and to read one thread and one message. Note anything odd with the exact message. The server logs only static text to stderr, and Claude Desktop keeps MCP logs.
5. Start a session, say "continue the work towards v1", and it plans the fix chunk.

### Maintainer steps outside the chunks

- Merge each chunk's pull request when `ci-success` is green.
- **Sign in once** (needs a Google Cloud OAuth client of type "Desktop app" with the Gmail API enabled, and a Google account that is a test user of it; a "Web application" client is refused on purpose). It only needs the phase 2 code, so it can happen as soon as phase 2 builds. `cargo build --release --locked`, then `target/release/gmail-mcp auth --credentials <the downloaded client_secret JSON>`. Open the printed address in a browser, approve read-only access, wait for the terminal to say it is signed in (macOS may ask whether `gmail-mcp` may accept incoming connections: it listens on 127.0.0.1 only, for up to 5 minutes). Delete the JSON, empty the Trash, run `scripts/verify-no-plaintext-secrets.sh`; it must exit 0.
- Likely trouble spots for the sign-in: a consent screen in "Testing" status issues refresh tokens that expire after 7 days (Google's OAuth overview page says so); publishing it "In production" avoids that at the price of the unverified-app warning and a 100-user cap (verify against Google's current docs before writing SETUP.md). A Google account that is not a test user is never redirected, so the sign-in times out. macOS may ask for Keychain access again after a rebuild (the binary is ad-hoc signed).
- Optional: `cargo test --locked --test keychain_macos -- --ignored` runs the Keychain tests on the Mac; they create and remove a throwaway item in the login keychain.

## Fixed decisions for the beta

Deliberately cheap; do not reopen them without the maintainer.

1. The MCP layer is `rmcp`, as ADRs 0004, 0008 and 0009 say: blocking `ureq` stays, tokio is only the runtime (current thread), tool handlers call the blocking code through `spawn_blocking`. (The maintainer chose this on 2026-11-25 over a hand-written protocol layer, knowing it costs more.)
2. Exactly four tools, as in the README table, with no flags or modes (0014). `max_results` defaults to 10 and is at most 25.
3. A search is one list call plus one metadata read per hit, one after another. Bounded parallelism (five at a time, 0008) stays planned.
4. No pagination (`pageToken` is unused), no retry or backoff, except one refresh and retry after a 401.
5. `get_thread` and `get_message` read with `format=full`. A response over `MAX_RESPONSE_BYTES` becomes a static error that suggests `get_message`.
6. Bodies: `text/plain` first, otherwise `html_to_text`; attachments are metadata only; MIME depth 8, at most 200 parts.
7. Every email-derived string, label names included, goes through `text::Untrusted`, the notice line comes first, and ids come only from validated `ResourceId`s.
8. Errors are static strings chosen by HTTP status. No Google response body appears in any message or log.
9. Access tokens live in memory only; every token response goes through `policy::check_grant`; credentials load lazily on the first tool call.
10. Logging is static messages to stderr through `log`.
11. No subagents, no review fan-out, no extra tests, no extra docs beyond what a chunk lists.

## Progress log

Append one line per finished chunk: date, chunk, result, branch or commit, calls used (rough), notes.

| Date | Chunk | Result | Branch or commit | Calls | Notes |
|---|---|---|---|---|---|
| 2026-11-25 | planning | Beta v1 plan written (this file) | `feat/auth` | | `rmcp` kept (maintainer's choice); chunks as above |

## After the beta: v1.0

Its own plan and budget, decided by the maintainer once the beta has been tested (rough guess $20 to $50). Candidates, roughly in order:

- One independent review of the phase 3 code, pointed at: wrapping of every email-derived field, id and query handling, token and scope handling, error text, and panics on hostile payloads.
- Hardening: bounded parallel search, pagination, large threads, backoff, a command that removes the stored credentials, broader hostile-payload tests.
- Documentation: the final README wording (drop "will do"; the dated, cited "why this exists" claim re-checked; honest limits revisited), `SETUP.md` (click-by-click Google Cloud steps; the 7-day expiry and the "In production" trade-off; commands that are paste-and-run), `docs/AUDIT.md` (the "audit in about ten minutes" guide, the roughly 400 security-critical lines first, a command per README claim), the Claude Desktop configuration once the place for the third-party deployment is known.
- The release: dry-run `release.yml` with `workflow_dispatch`, a release pull request (version, lockfile, CHANGELOG), and the maintainer tags the first version (a tag ruleset limits who can). **Tag and publish only on the maintainer's word.** Details: [maintainers/releasing.md](maintainers/releasing.md).

## Backlog (small; none requested)

Beta shortcuts (debt on purpose; add to this list whenever a chunk takes another):

- Search reads each hit one after another; no pagination; no backoff; one account only.
- `get_thread` of a very long thread can exceed the response limit; the beta returns a static error.
- A token response without a `scope` field is refused; whether Google ever omits it is unchecked.
- Tool calls share one session behind a lock, so they run one at a time; cancellation is not handled.
- Tests are the minimum listed per chunk; no review beyond the self-check.

Older items:

- No command removes the stored credentials (the README gives the Keychain steps).
- `scripts/verify-no-plaintext-secrets.sh` misses some token serialisations and does not read the Trash.
- Nothing pins that `auth::run` drops the listener before the code exchange.
- The static scans are textual: a `bind` or `connect` spelled another way passes.
- Secrets are not zeroized in memory.
- A local program that floods the sign-in port can make the sign-in time out (documented in SECURITY.md).
- Credential stores for Linux and Windows are TODO (ADR 0006); they fail closed today.
- Stale branches: remote `docs/readme-doc-check` (old pre-squash history plus one unmerged README line that lists the rustdoc check in the development commands), local `chore/scaffold` and `feat/policy-core`.
- The maintainer's own checklist (repository settings, rulesets) lives outside the repository on purpose.

## Code map

| Path | Role |
|---|---|
| `src/main.rs`, `src/cli.rs` | Arguments (`cli::parse` returns `Task::{Serve, Auth, Help, Version}`) and exit codes (usage error 2, sign-in failure 1). `serve` is the stub chunk 2 replaces |
| `src/policy.rs` | Every rule and limit: the scope, `check_grant`, the route table (`authorize`; the Gmail reads and the token POST), `header_allowed`, `ResourceId::parse` (bounded ids of `[A-Za-z0-9_-]`), the size and time limits (`MAX_RESPONSE_BYTES`, `MAX_OUTPUT_CHARS`, `MAX_FIELD_CHARS`, `REQUEST_TIMEOUT` and others) |
| `src/http.rs` | `Egress::send`, the one network function: HTTPS only, no redirects, no proxy, response, request and time limits. All Gmail and token traffic goes through it |
| `src/text.rs` | `sanitize`, `truncate`, `Untrusted` (the per-call nonce wrapper with one shared budget: `wrap(field, text)`, `wrap_body(text)`, `notice()`, `exhausted()`), `html_to_text` |
| `src/auth.rs` | The sign-in: `run`, `authenticate`, `login`, the loopback listener, `Guarded` (the `oauth2` HTTP adapter over the egress guard), `parse_client_file` |
| `src/store.rs`, `src/store/keychain.rs` | `CredentialStore` (`load`, `save`, `remove`), `Credentials` (cannot hold another scope), `Secret`, the `Unavailable` stub, `platform()`, the macOS `Keychain` |
| `src/log.rs` | stderr logging with `&'static str` messages only; `consent_text` is the single exception (ADR 0015) |
| planned | `src/gmail.rs`, `src/session.rs`, `src/tools.rs` (chunk 1), `src/server.rs` (chunk 2) |
| `tests/` | `static_policy` (source scans), `egress_policy` (route table), `deps_policy` (direct dependencies), `auth_flow`, `auth_redirect`, `auth_client_file`, `consent_url`, `store_policy`, `keychain_macos` (ignored), `secrets_script`, `cli_binary`, `ci_workflow`; planned: `stdio_smoke` |
| `scripts/` | `verify-no-plaintext-secrets.sh` (the maintainer runs it after the sign-in), `release-notes.sh` |
| `.github/workflows/` | `ci.yml` (all jobs, aggregate check `ci-success`), `security.yml`, `scorecard.yml`, `release.yml` |

## Working agreements with the maintainer

- Present a plan and wait for the green light before each chunk (the maintainer's request, 2026-11-25).
- Never run `gmail-mcp auth` or `serve` against a real Google account, never touch the real mailbox, and never run the `#[ignore]`d Keychain tests on the maintainer's machine without asking. Live checks are the maintainer's. Do not read the maintainer's application configuration beyond key names.
- Do not install tools on the maintainer's machine (toolchains, `cargo-deny`, `zizmor`, `gh`). Say what is missing and what it would catch.
- Dependencies stay minimal: official or very widely used crates, each justified, and ask first (AGENTS.md).
- Git: pushing a feature branch needs no ask; never force-push; never push to `main`; open a pull request or merge only when asked (squash merge, by the maintainer).
- Personal checklists, Google Cloud click-paths and repository settings stay out of the repository. No local usernames, home paths or addresses in any file.
- The product is not macOS-only: the Keychain comes first, other platforms fail closed and get their own store later.
- Reports are short: what was built, each check's result (pass or fail), what the maintainer still has to verify by hand. Commands are paste-and-run. Challenge a weak requirement before building it.

## Keeping a session cheap

- The multi-agent review in phase 2 (about 4,000 subagent calls) took roughly nine tenths of that phase's token spend; the implementation itself was cheap. Implement in the main session, review once at most, fix. Use a larger fan-out only when the maintainer asks for it.
- One chunk per session. Start the next in a fresh session from this file instead of carrying the old chat: every model call re-reads the whole context, and the prompt cache expires after about five idle minutes, after which the whole context is billed again as new input.
- Read what the chunk names, not whole files: `grep -n` and line ranges. Trim command output (`| tail -n 40`); clippy and test output can be enormous.
- Iterate with the narrowest test (`cargo test --locked --test <name>`), run the full suite once before pushing, and read an ADR's Implementation line before the whole record.
- Batch independent calls in one message.
