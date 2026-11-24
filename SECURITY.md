# Security policy

GMail-MCP exists to limit what an AI assistant can do with a Gmail account, so security reports are taken seriously.

## Supported versions

The project is pre-1.0. Only the latest release and `main` receive fixes.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability reporting:

1. Go to <https://github.com/BorntraegerMarc/GMail-MCP/security/advisories/new> (or **Security → Advisories → Report a vulnerability**).
2. Describe the problem, how to reproduce it, and the impact.

This is a one-person, spare-time project. You can expect an acknowledgement within about a week and a fix or a clear answer on a best-effort basis. Reporters are credited in the advisory unless they prefer otherwise.

## What counts as a vulnerability

In scope, because they break the project's stated guarantees:

- Any way to make the server send (reply-send included), forward, create or change a draft, delete, trash, untrash, mark as spam, label, or change settings or filters in Gmail, or to make it request a scope other than `gmail.readonly`.
- Any way to make the server contact a host other than the allowlisted Google hosts, or to bypass the single egress guard.
- Any way to read, log, or leak OAuth tokens, client secrets, email content, subjects or recipients (including via logs, stdout, error messages or files on disk).
- Path or ID injection into Gmail API requests.
- A bypass of the untrusted-content wrapping or sanitising that leads to concrete harm.
- Weaknesses in the build, release or CI configuration (for example unpinned actions or over-broad workflow permissions).

Out of scope:

- Prompt injection as a general class. The wrapping reduces the risk but cannot eliminate it; this limit is documented in the README.
- Vulnerabilities in Google services, in your operating system, or in an AI client.
- Vulnerabilities in a dependency that are already published as RustSec advisories (Dependabot and `cargo deny` track these); please report them upstream.
- Issues that need an attacker who already controls your user account or your credential store (for example the macOS Keychain).
