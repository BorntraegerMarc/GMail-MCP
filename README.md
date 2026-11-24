# GMail-MCP

[![CI](https://github.com/BorntraegerMarc/GMail-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/BorntraegerMarc/GMail-MCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A secure, minimal Gmail MCP server in Rust for personal Gmail accounts, while Google's official one is gated.**
Search and read your mail from Claude, and nothing else: no send, no drafts, no delete, no settings, no telemetry. Credentials stay in your operating system's credential store (the macOS Keychain today).

> **Status: early development.** This repository currently contains the project scaffold, the policy core (the one OAuth scope, the egress guard and the handling of untrusted email content) and the sign-in (`gmail-mcp auth`, which stores read-only credentials in the macOS Keychain), but not yet a working server. The server lands phase by phase, one reviewable pull request each; progress is in [CHANGELOG.md](CHANGELOG.md).
>
> **Unofficial.** Not affiliated with, endorsed by, or sponsored by Google or Anthropic. "Gmail" is a trademark of Google LLC.

## Why this exists

Google's official Gmail MCP server (`gmailmcp.googleapis.com`) is [available as part of the Google Workspace Developer Preview Program](https://developers.google.com/workspace/gmail/api/guides/configure-mcp-server). Per Google's [program page](https://developers.google.com/workspace/preview), applicants need a Google Workspace account, and the application form states that Gmail addresses, service accounts and Google Groups are not accepted. As of November 2026 that means a personal `@gmail.com` account cannot enroll.

This project is a small stand-in for that gap. It also takes the opposite stance on power: the official server's documented scopes include the broad `gmail.modify`; this one requests `gmail.readonly` and nothing else.

## What it will do

Four tools, exactly these, and no others:

| Tool | What it does |
|---|---|
| `list_labels` | List your Gmail labels |
| `search_threads` | Gmail search syntax; returns id, subject, sender, date, snippet (max 25) |
| `get_thread` | Messages with headers and a plain-text body (capped, with a visible truncation marker) |
| `get_message` | One message; attachments are metadata only, never downloaded |

**Deliberately not implemented, and never will be:** send (reply-send included), forward, create or change drafts, delete, trash, untrash, spam, label changes, filters, settings.

### Replying to a mail

The server does not compose mail. To answer an email, ask Claude for a suggested reply: it writes the text into a Markdown file (in a folder you choose, with its own file tools), and you copy it into your mail client and send it yourself.

### One permission, enforced by Google

`gmail-mcp auth` requests only `gmail.readonly`, and refuses to store a grant that holds any other scope. With that scope Google refuses every write, whatever this code does: the server cannot send, draft, change or delete mail. Inside the process, the egress guard says the same thing a second time (the Gmail host has no route but `GET`) and does what the scope cannot: it keeps the server from talking to any other host.

## Security design at a glance

| Threat | Mitigation |
|---|---|
| Supply chain | A short list of direct dependencies (about eight planned), all official or very widely used, though the full tree is larger (about 140 crates expected; 82 so far on Linux and 87 on macOS, see [ADR 0004](docs/decisions/0004-dependency-policy-and-libraries.md)); exact pins, `Cargo.lock` committed, `cargo-deny` policy, Dependabot with cooldown, every GitHub Action pinned to a commit SHA, build-provenance attestation on releases |
| Credential theft | Tokens and client secret only in the OS credential store (the macOS Keychain today); no token or secret files (`scripts/verify-no-plaintext-secrets.sh` checks for leftovers); never logged; fails closed if the store is unavailable |
| Prompt injection via email | The server can only read: Google's read-only scope refuses every write, so even a fully steered server cannot send, draft or change anything. Email content is wrapped in per-call random delimiters, sanitised, and labelled as data |
| Silent exfiltration by the server | One audited egress function allows only `oauth2.googleapis.com` and `gmail.googleapis.com`, with a fixed method and path allowlist; static tests fail on anything else; no telemetry |

## Honest limits

- The server can still read all of your mail: `gmail.readonly` covers every message, and it is the narrowest scope that returns message bodies. Grant it only to an app you trust, and revoke it in your Google account when you stop using the server.
- Wrapping email content as untrusted data **reduces** prompt-injection risk; it does **not** eliminate it. An assistant that reads a hostile email while also holding other tools (file writing, web fetch, other MCP servers) can still be manipulated into misusing them: writing a misleading suggested reply, or leaking what it read through a URL. This server cannot prevent that. Read a suggested reply before you paste it.
- The client secret JSON that you download from Google Cloud stays on disk, in plaintext, until you delete it: `gmail-mcp auth` copies it into the Keychain, tells you to delete the file, and never deletes your files itself. Deleting it in Finder only moves it to the Trash, so empty the Trash too. `scripts/verify-no-plaintext-secrets.sh` lists what is left (it reads the project, `~/.config`, the temporary folder and `~/Downloads`; it does not read the Trash).
- To remove the stored credentials, delete the item named `gmail-mcp` (account `oauth-credentials`) in Keychain Access, or run `security delete-generic-password -s gmail-mcp -a oauth-credentials`, and remove this app's access in your Google account.
- While `gmail-mcp auth` runs, a listener on `127.0.0.1` waits for Google's redirect for up to five minutes. Other programs on your machine can connect to it, but cannot complete the sign-in or end it early without the one-time `state` of that sign-in; one that floods the port can make it time out, and you run it again. The program prints the consent address and you open it yourself; it starts no browser.
- A locally built binary is ad-hoc signed, so macOS may ask for Keychain access again after a rebuild.
- An OAuth app in "Testing" mode has refresh tokens that expire after 7 days. Publishing the consent screen as "In production" (unverified, single user) avoids that, at the cost of Google's unverified-app warning screen and a 100-user cap.
- **Platforms:** secret storage is implemented for macOS only (the Keychain). Linux and Windows are TODO: until a secure store exists there, the server starts but every tool call fails closed, and it never falls back to a file.

## Development

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dependency policy and the rules about what may never be added, [SECURITY.md](SECURITY.md) to report a vulnerability privately, [docs/decisions/](docs/decisions/) for why the design is the way it is, and [docs/maintainers/releasing.md](docs/maintainers/releasing.md) for the release process.

## License

[MIT](LICENSE)
