# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Added

- Repository scaffold: stub crate, CI (fmt, clippy, tests, MSRV, docs, cargo-deny, zizmor,
  dependency review), CodeQL, OpenSSF Scorecard, release workflow with build-provenance
  attestation, Dependabot, security policy, contribution guide, agent instructions
  (`AGENTS.md`, imported by `CLAUDE.md`) and decision records in `docs/decisions/`.
- Pipeline jobs that need a public repository (dependency review, CodeQL, Scorecard, release attestation) are skipped while the repository is private.
- Policy core (phase 1 of the build). There is still no server: the binary refuses to run until the next phases land.
  - The server only reads mail. It requests one OAuth scope, `gmail.readonly`, and has no tool, route or dependency that composes, drafts or sends anything. Replies are suggested by the assistant in a Markdown file that you copy into your mail client yourself (decision record 0014).
  - `policy`: the one scope, the egress route table (the Gmail host has no route but `GET`; only listed query parameters and values pass), identifier validation and every size and time limit.
  - `http`: the egress guard. HTTPS only, no redirects, no proxy (also not from the environment), response, request and time limits, a header allowlist, and no body on a `GET`.
  - `text`: sanitising and wrapping of email content as untrusted data (per-call nonce delimiters, invisible Unicode stripped, line breaks normalised, one output budget that counts delimiters, `[truncated]` markers) and a hand-written, single-pass HTML-to-text converter that cannot panic and whose cost follows the input length only (decision record 0013).
  - `log`: stderr logging with static messages only.
  - Tests: an allowlist table with hostile requests and query parameters, source scans (forbidden endpoints, methods, scopes, hosts, network and process APIs, mail composition, loggers, printing), a direct-dependency allowlist, transport tests against a local server, a proxy-environment test, and property tests on untrusted input.
  - Dependencies: `ureq` and `oauth2`, plus `proptest` for tests, all pinned exactly (82 crates in the normal tree). `cargo-deny` now also fails a second `ureq` version and bans `lettre`.
- Sign-in (phase 2 of the build). `gmail-mcp auth [--credentials <client_secret.json>]` runs the OAuth authorization-code flow with PKCE for a Desktop-app client that you created, and stores the read-only credentials in the macOS Keychain. There is still no server: `serve` refuses to run until the next phase.
  - It asks Google for `gmail.readonly` only, and refuses to store a grant that holds any other scope, one that Google does not describe, or one without a refresh token. A stored item that holds more than the read-only scope is refused when it is read.
  - You open the consent address yourself: the program starts no browser and no other process. A listener on 127.0.0.1 receives Google's redirect, serves connections side by side so that silent ones cannot hold it up, acts only on a request that carries the `state` of this sign-in, and closes as soon as the code arrives. The code exchange goes through the egress guard (decision record 0015).
  - The credentials are one Keychain item (client id, client secret, refresh token, scopes). Other platforms fail closed and never fall back to a file. `scripts/verify-no-plaintext-secrets.sh` lists leftovers: files that look like Google OAuth secrets, by name or by text, printing paths and never contents.
  - A narrow macOS CI job (lints, the Keychain tests on a throwaway keychain, docs) runs when a pull request touches the store, the manifests or the workflow.
  - Dependencies: `serde_json` (already in the tree) and, on macOS only, `security-framework`. The Linux tree stays at 82 crates; the macOS build adds 5.
