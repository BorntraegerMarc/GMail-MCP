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
  - `policy`: the permission model (read-only, or drafts), the two OAuth scopes, the egress route table, identifier validation and every size and time limit.
  - `http`: the egress guard. HTTPS only, no redirects, no proxy, response, request and time limits, and a route table that admits no send, delete, label, settings or attachment request and the draft route only in drafts mode.
  - `text`: sanitising and wrapping of email content as untrusted data (per-call nonce delimiters, invisible Unicode stripped, one shared output budget, `[truncated]` markers) and size- and depth-bounded HTML-to-text conversion.
  - `draft`: building a draft with header-injection checks, plain ASCII addresses only, caps, threading headers and Bcc kept.
  - `log`: stderr logging with static messages only.
  - Tests: an allowlist table with hostile requests, source scans for forbidden endpoints, methods, scopes, hosts, network and process APIs and printing, a direct-dependency allowlist, and property tests on untrusted input.
  - Dependencies: `ureq`, `oauth2`, `lettre` and `html2text`, plus `proptest` for tests, all pinned exactly (108 crates in the normal tree). `cargo-deny` now also fails a second `ureq` version.
