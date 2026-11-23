# GMail-MCP

[![CI](https://github.com/BorntraegerMarc/GMail-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/BorntraegerMarc/GMail-MCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A secure, minimal Gmail MCP server in Rust for personal Gmail accounts, while Google's official one is gated.**
Search and read your mail from Claude, optionally create drafts, and nothing else: no send, no delete, no settings, no telemetry. Credentials stay in the macOS Keychain.

> **Status: early development.** This repository currently contains the project scaffold only. The server lands phase by phase, one reviewable pull request each; progress is in [CHANGELOG.md](CHANGELOG.md).
>
> **Unofficial.** Not affiliated with, endorsed by, or sponsored by Google or Anthropic. "Gmail" is a trademark of Google LLC.

## Why this exists

Google's official Gmail MCP server (`gmailmcp.googleapis.com`) is [available as part of the Google Workspace Developer Preview Program](https://developers.google.com/workspace/gmail/api/guides/configure-mcp-server). Per Google's [program page](https://developers.google.com/workspace/preview), applicants need a Google Workspace account, and the application form states that Gmail addresses, service accounts and Google Groups are not accepted. As of November 2026 that means a personal `@gmail.com` account cannot enroll.

This project is a small stand-in for that gap. It also takes the opposite stance on power: the official server's documented scopes include the broad `gmail.modify`; this one requests `gmail.readonly` by default and adds `gmail.compose` only when you ask for it.

## What it will do

Five tools, exactly these, and no others:

| Tool | Needs `--allow-drafts` | What it does |
|---|---|---|
| `list_labels` | no | List your Gmail labels |
| `search_threads` | no | Gmail search syntax; returns id, subject, sender, date, snippet (max 25) |
| `get_thread` | no | Messages with headers and plain-text body (capped, with a visible truncation marker) |
| `get_message` | no | One message; attachments are metadata only, never downloaded |
| `create_draft` | **yes** | Creates a draft. It is **not sent**; you review and send it yourself in Gmail |

**Deliberately not implemented, and never will be:** send (reply-send included), forward, delete, trash, untrash, spam, label changes, filters, settings.

### Two layers of permission

1. **Google-side scope** (enforced by Google): `gmail-mcp auth` requests only `gmail.readonly`. `gmail-mcp auth --allow-drafts` adds `gmail.compose`. With a read-only grant, creating a draft is impossible even if the code had a bug.
2. **Server-side tool list**: `gmail-mcp serve` exposes the four read tools. `gmail-mcp serve --allow-drafts` adds `create_draft`.

## Security design at a glance

| Threat | Mitigation |
|---|---|
| Supply chain | A short list of direct dependencies (about ten planned), all official or very widely used, though the full tree is larger (161 crates measured for the planned set; see [ADR 0004](docs/decisions/0004-dependency-policy-and-libraries.md)); exact pins, `Cargo.lock` committed, `cargo-deny` policy, Dependabot with cooldown, every GitHub Action pinned to a commit SHA, build-provenance attestation on releases |
| Credential theft | Tokens and client secret only in the macOS Keychain; no token or secret files; never logged; fails closed if the Keychain is unavailable |
| Prompt injection via email | No tool can send, delete or change settings; worst case is a draft you see before anything is sent. Email content is wrapped in per-call random delimiters, sanitised, and labelled as data |
| Silent exfiltration by the server | One audited egress function allows only `oauth2.googleapis.com` and `gmail.googleapis.com`, with a fixed method and path allowlist; static tests fail on anything else; no telemetry |

## Honest limits

- `gmail.compose` is the narrowest scope Google offers for drafts, and it technically permits sending at the API level. Google has no draft-only scope. The guarantee that nothing is sent comes from this code never calling a send endpoint, and from the egress allowlist and tests that enforce it. If you do not need drafts, do not grant the scope.
- Wrapping email content as untrusted data **reduces** prompt-injection risk; it does **not** eliminate it. An assistant that reads a hostile email while also holding other tools (web fetch, other MCP servers) can still be manipulated into leaking data through those tools, which this server cannot prevent.
- A locally built binary is ad-hoc signed, so macOS may ask for Keychain access again after a rebuild.
- An OAuth app in "Testing" mode has refresh tokens that expire after 7 days. Publishing the consent screen as "In production" (unverified, single user) avoids that, at the cost of Google's unverified-app warning screen and a 100-user cap.
- macOS only.

## Development

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dependency policy and the rules about what may never be added, [SECURITY.md](SECURITY.md) to report a vulnerability privately, [docs/decisions/](docs/decisions/) for why the design is the way it is, and [docs/maintainers/releasing.md](docs/maintainers/releasing.md) for the release process.

## License

[MIT](LICENSE)
