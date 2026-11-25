# Roadmap and resume guide

Where the build stands, what comes next, and what a fresh session needs to carry on without the old chat. Update this file whenever a phase lands or a step finishes. The story so far, with the lessons, is in [DEVELOPMENT-LOG.md](DEVELOPMENT-LOG.md); the reasons behind the design are in [decisions/](decisions/README.md). Last updated: 2026-11-25.

## State at a glance

| Phase | Scope | State |
|---|---|---|
| 0, 0b | Scaffold, CI and security tooling, agent instructions, decision records | Merged: #1 (`b8923a0`), toolchain bump #2 (`42b0aae`) |
| 1 | Policy core: the one scope, the egress guard, untrusted-content handling | Merged: #3 (`13eb58e`) |
| 2 | Sign-in: `gmail-mcp auth`, the Keychain store, the scope refusal | Code finished and pushed on branch `feat/auth` (last code commit `1caede0`; the hand-off docs follow it). No pull request yet, and CI has never run on it |
| 3 | Gmail client, the four read tools, the MCP server over stdio | Not started |
| 4 | Full README, SETUP.md, AUDIT.md, first release | Not started |

**Works today** (by tests; never yet against Google): `gmail-mcp auth [--credentials <client_secret.json>]` runs the sign-in and stores read-only credentials in the macOS Keychain. Other platforms fail closed and never fall back to a file.

**Does not exist yet:** any Gmail call, any tool, any MCP server. `gmail-mcp serve` says it is not implemented and exits with code 2, so the product cannot be used from Claude until phase 3 lands.

**"Usable by the maintainer"** means steps A to C below plus a Claude Desktop configuration snippet. Step D (full documentation and a release) is for sharing the project.

Size at the end of phase 2: about 4,300 lines in `src/` (a good part is unit tests), about 200 tests (4 `#[ignore]`d), 82 crates in the Linux dependency tree and 87 on macOS, 15 decision records.

## Never exercised yet

Assume nothing about these until a run proves it:

- Every CI job on the phase 2 branch. The first run of the Linux jobs with the new code, `cargo-deny`, `zizmor`, the MSRV (1.89) build and the macOS job `macos-store` has not happened. The MSRV job does not compile the macOS-only code at all. The 1.89 toolchain, `cargo-deny` and `zizmor` are not installed on the maintainer's machine, so CI is where they run first.
- `gmail-mcp auth` against Google, and the Keychain code on a real keychain (its tests are `#[ignore]`d; CI runs them on a throwaway keychain).
- `release.yml`, not even as a dry run.

## Resume in ten minutes

1. `AGENTS.md` loads on its own (`CLAUDE.md` imports it). Read this file next, then the decision-record index ([decisions/README.md](decisions/README.md)), then only the records the step in hand names. Do not read all of `src/`: the code map below says where things are. Read the development log only for history, or when a check fails in a way you do not recognise (its pitfalls section lists the ones met so far).
2. `git status` and `git log --oneline -8`. Find out whether the phase 2 pull request exists and what CI says. `gh` is not installed on the maintainer's machine; use the GitHub MCP tools (number-based reads such as `pull_request_read` work; list calls that return arrays have failed). Dependabot may have opened pull requests: they are the maintainer's to review.
3. Baseline: `cargo fmt --all --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked`. It was green at the end of phase 2. If it is not, fix that before anything else.
4. Take the first unfinished step under "Next steps".

Kick-off prompt for a new chat:

> Resume the GMail-MCP build. Read AGENTS.md and docs/ROADMAP.md, not old chats. First check whether the phase 2 pull request is merged and what CI says, then do the first open step in "Next steps". Keep it lean: no multi-agent workflows, one targeted review at the end, a short report. Ask before adding dependencies.

## Code map

| Path | Role |
|---|---|
| `src/main.rs`, `src/cli.rs` | Arguments (`cli::parse` returns `Task::{Serve, Auth, Help, Version}`) and exit codes (usage error 2, sign-in failure 1). `serve` is the stub phase 3 replaces |
| `src/policy.rs` | Every rule and limit: the scope, `check_grant`, the route table (`authorize`), `header_allowed`, `ResourceId::parse` (bounded ids of `[A-Za-z0-9_-]`), the size and time limits (`MAX_RESPONSE_BYTES`, `MAX_OUTPUT_CHARS`, `MAX_FIELD_CHARS`, `REQUEST_TIMEOUT` and others) |
| `src/http.rs` | `Egress::send`, the one network function: HTTPS only, no redirects, no proxy, response, request and time limits. All Gmail and token traffic goes through it |
| `src/text.rs` | `sanitize`, `truncate`, `Untrusted` (the per-call nonce wrapper with one shared budget: `wrap(field, text)`, `wrap_body(text)`, `notice()`, `exhausted()`), `html_to_text` |
| `src/auth.rs` | The sign-in: `run`, `authenticate`, `login`, the loopback listener, `Guarded` (the `oauth2` HTTP adapter over the egress guard), `parse_client_file` |
| `src/store.rs`, `src/store/keychain.rs` | `CredentialStore`, `Credentials` (cannot hold another scope), `Secret`, the `Unavailable` stub, `platform()`, the macOS `Keychain` |
| `src/log.rs` | stderr logging with `&'static str` messages only; `consent_text` is the single exception (ADR 0015) |
| `tests/` | `static_policy` (source scans), `egress_policy` (route table), `deps_policy` (direct dependencies), `auth_flow`, `auth_redirect`, `auth_client_file`, `consent_url`, `store_policy`, `keychain_macos` (ignored), `secrets_script`, `cli_binary`, `ci_workflow` |
| `scripts/` | `verify-no-plaintext-secrets.sh` (the maintainer runs it after the sign-in), `release-notes.sh` |
| `.github/workflows/` | `ci.yml` (all jobs, aggregate check `ci-success`), `security.yml`, `scorecard.yml`, `release.yml` |

## Next steps, in order

Owner: **M** is the maintainer (an agent cannot do it), **A** is an agent session.

### A. Land phase 2 (M, then A)

- M: open the pull request from `feat/auth` to `main`. The body needs the PR security note (CONTRIBUTING.md): no new host, method or scope; adds the loopback listener and the consent-address constant; new dependencies are `serde_json` (already in the tree) and, on macOS only, `security-framework` (5 more crates on macOS; Linux stays at 82).
- A: read CI once it has finished. The first run of `cargo-deny`, `zizmor`, the 1.89 MSRV build and `macos-store` is where surprises are most likely. Fix on the same branch and push; never weaken a check to get green.
- M: squash-merge when `ci-success` is green.

### B. First live sign-in (M)

Needs a Google Cloud OAuth client of type "Desktop app" with the Gmail API enabled (a "Web application" client is refused on purpose), and a Google account that is a test user of it.

1. `cargo build --release --locked`, then `target/release/gmail-mcp auth --credentials <the downloaded client_secret JSON>`.
2. Open the printed address in a browser, approve read-only access, and wait for the terminal to say it is signed in. macOS may ask whether `gmail-mcp` may accept incoming connections: it listens on 127.0.0.1 only, for up to 5 minutes.
3. Delete the JSON, empty the Trash, run `scripts/verify-no-plaintext-secrets.sh`. It must exit 0.
4. Likely trouble spots, to hand to an agent: a consent screen in "Testing" status issues refresh tokens that expire after 7 days (stated on Google's OAuth overview page); publishing it "In production" avoids that at the price of the unverified-app warning and a 100-user cap (verify against Google's current docs when writing SETUP.md). A Google account that is not a test user is never redirected, so the sign-in times out. macOS may ask for Keychain access again after a rebuild (the binary is ad-hoc signed).
5. Optional: `cargo test --locked --test keychain_macos -- --ignored` runs the Keychain tests on the Mac; they create and remove a throwaway item in the login keychain.

### C. Phase 3: the Gmail client and the MCP server (A)

Decisions already taken, so do not reopen them: exactly four tools, no flags or modes (0014); the Gmail host has no route but `GET`, and ids and query parameters are constrained by the route table (0003, 0014); every email-derived string goes through `text::Untrusted` (0005); blocking `ureq` inside `spawn_blocking`, tokio only as the MCP runtime (0008); stdio only (0009); credentials only from the store, loaded lazily so `initialize` and `tools/list` work without the Keychain (0006); nothing on stdout, static log messages only (AGENTS.md).

One pull request, branched from `main` once phase 2 has merged.

1. **Confirm the MCP layer, then measure.** The plan is `rmcp` (the official SDK; features `server`, `macros` and `transport-io` only), `tokio` (`rt`, `macros`), `serde` and `base64`, all pinned exactly (ADR 0004). Before adding them, check the current `rmcp` version and its MSRV (the 1.89 floor came from `uuid` via `rmcp`, measured 2026-11-23), the crate count `cargo tree` gives (the README expects about 140), and the licences. The maintainer accepts `rmcp`; any other new crate is an ask-first item. One question worth asking once: a hand-written JSON-RPC layer for four tools would keep the tree near today's size, but it needs its own ADR and protocol tests against a real client.
2. **`src/gmail.rs`.** Typed read calls over a `Transport` trait (production: `Egress` plus the bearer token; tests: a fake). Labels list. Threads list with `q` and `maxResults` (cap 25, default 10), then a metadata fetch per thread for subject, sender and date (N+1 reads, bounded parallelism of 5 with scoped threads). Thread and message fetch with `format=full`. A MIME part walk with a depth and part-count limit (release builds abort on panic, so hostile nesting must not overflow the stack). Base64url body decoding; prefer `text/plain`, otherwise `html_to_text`. Attachments as metadata only (name, type, size); there is no route to fetch them. Check which query parameters the route table already passes before adding any (a new allowed parameter is an ask-first item), and check real thread sizes against `MAX_RESPONSE_BYTES`: a long thread may need message-by-message fetching.
3. **Access token handling.** Refresh-token grant against the token endpoint through the egress guard (client id and secret in the body, as in `auth`; `auth::Guarded` and the `oauth2` types can be reused). Access token and expiry in memory only. The scope in every token response goes through `policy::check_grant` and fails closed on anything but exactly `gmail.readonly`; decide how to treat a response with no `scope` field (fail closed unless a live check shows Google omits it). An `invalid_grant` answer gives a static message telling the user to run `gmail-mcp auth` again. No token, header or response body in any log or error text.
4. **`src/tools.rs` and `serve`.** The four tools with read-only annotations. Arguments are validated before any request (`ResourceId::parse`, `max_results` 1 to 25, a bound on the query length). Output is built only through `text::Untrusted` with its shared budget (`MAX_OUTPUT_CHARS`, visible `[truncated]` marker). Tool errors are static strings. Replace the stub in `main.rs`; tokio `current_thread` runtime.
5. **Tests.** A fake `Transport` for search, thread (multipart, HTML-only, truncation), message (attachment metadata only), id and path-traversal rejection, hostile content (every field wrapped, look-alike delimiters), refresh and the scope re-check, and hostile payload shapes (missing fields, bad base64, deep nesting, huge parts). `tests/stdio_smoke.rs`: start the real binary; `initialize` and `tools/list` must return exactly the four tools without a Keychain, and a `tools/call` without credentials must fail closed with a clear message. Update `tests/static_policy.rs` narrowly (the async runtime and `rmcp` only in the files that need them, no `tokio::net`, still no process APIs) and `tests/deps_policy.rs` (the allowlist), each with a comment saying why.
6. **Docs in the same PR.** Implementation lines and index rows of ADRs 0004, 0005, 0006, 0008, 0009 and 0014; CHANGELOG; README (status, tools, crate counts, security table); the PR security note with the dependency list and crate count.
7. **Review, proportionate.** One independent reviewer on the diff, pointed at: wrapping of every email-derived field, id and query handling, token and scope handling, error text, and panics on hostile payloads. Fix, push. Do not repeat the phase 2 fan-out.
8. **First live run (M).** After step B and a configuration snippet: start the server from Claude Desktop, list labels, search, read one thread, and report anything odd.

### D. Phase 4: documentation and the first release (A, M for the tag)

- `README.md`: final wording (drop "will do"), build from source, the dated and cited "why this exists" claim re-checked, honest limits revisited, real crate counts.
- `SETUP.md`: click-by-click Google Cloud steps (project, Gmail API, consent screen "External" with a test user and only `gmail.readonly`, a Desktop-app client; the "use this client for an AI-powered agent" option can stay unticked), the 7-day expiry and the "In production" trade-off, running `auth`, deleting the JSON and emptying the Trash, the verify script, and how to revoke access. Commands must be paste-and-run with no manual editing.
- `docs/AUDIT.md`: the "audit in about ten minutes" guide: file by file, the roughly 400 security-critical lines first, and a command that checks each README claim.
- The Claude Desktop configuration: a command that prints the JSON block with the absolute path filled in, so no home path is committed. The third-party (Bedrock) deployment of Claude Desktop keeps its configuration in its own application-support folder, not the standard one: check read-only where before naming a path.
- The release: dry-run `release.yml` with `workflow_dispatch`, a release pull request (version, lockfile, CHANGELOG), and the maintainer tags `v0.1.0` (a tag ruleset limits who can). **Tag and publish only on the maintainer's word.** Details: [maintainers/releasing.md](maintainers/releasing.md).
- A last adversarial self-review of the finished code (exfiltration paths, header and path injection, deserialization); list what was checked and what changed.

### Questions only the maintainer can answer

- C1: `rmcp` as planned, or a hand-written protocol layer for a smaller tree?
- Whether to publish the consent screen "In production" (no 7-day expiry, but a warning screen and a 100-user cap) or to re-run `auth` weekly.
- When to tag the first release.

### Backlog (small; none requested)

- No command removes the stored credentials (the README gives the Keychain steps).
- `scripts/verify-no-plaintext-secrets.sh` misses some token serialisations and does not read the Trash.
- Nothing pins that `auth::run` drops the listener before the code exchange.
- The static scans are textual: a `bind` or `connect` spelled another way passes.
- Secrets are not zeroized in memory.
- A local program that floods the sign-in port can make the sign-in time out (documented in SECURITY.md).
- Credential stores for Linux and Windows are TODO (ADR 0006); they fail closed today.
- Stale branches: remote `docs/readme-doc-check` (old pre-squash history plus one unmerged README line that lists the rustdoc check in the development commands), local `chore/scaffold` and `feat/policy-core`.
- The maintainer's own checklist (repository settings, rulesets) lives outside the repository on purpose.

## Working agreements with the maintainer

- Never run `gmail-mcp auth` or `serve` against a real Google account, never touch the real mailbox, and never run the `#[ignore]`d Keychain tests on the maintainer's machine without asking. Live checks are the maintainer's.
- Do not install tools on the maintainer's machine (toolchains, `cargo-deny`, `zizmor`, `gh`). Say what is missing and what it would catch.
- Dependencies stay minimal: official or very widely used crates, each justified, and ask first (AGENTS.md).
- Git: pushing a feature branch needs no ask; never force-push; never push to `main`; open a pull request or merge only when asked (squash merge, by the maintainer).
- Personal checklists, Google Cloud click-paths and repository settings stay out of the repository. No local usernames, home paths or addresses in any file.
- The product is not macOS-only: the Keychain comes first, other platforms fail closed and get their own store later.
- Reports are short: what was built, each check's result (pass or fail), what the maintainer still has to verify by hand. Commands are paste-and-run. Challenge a weak requirement before building it.

## Keeping a session cheap

- The multi-agent review in phase 2 (about 4,000 subagent calls) took roughly nine tenths of that phase's token spend; the implementation itself was cheap. Implement in the main session, review once with a single targeted reviewer, fix. Use a larger fan-out only when the maintainer asks for it.
- One step per session. Start the next in a fresh session from this file instead of carrying the old chat: every model call re-reads the whole context, and the prompt cache expires after about five idle minutes, after which the whole context is billed again as new input.
- Iterate with the narrowest test (`cargo test --locked --test <name>`), run the full suite once before pushing, and read an ADR's Implementation line before the whole record.
