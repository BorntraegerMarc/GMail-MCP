# 0006. Credentials only in the OS credential store (macOS Keychain first), fail closed

- Status: Accepted (2026-11-23)
- Implementation: Not implemented yet. Guardrails today include the `.gitignore` entries for credential-like file names, the clippy print lints in `Cargo.toml`, and the secrets rules in CONTRIBUTING.md and the PR template. Planned: the log module (phase 1); the credential-store interface, the macOS Keychain store, the fail-closed stub for other platforms, `gmail-mcp auth`, the secret type and a script that scans for plaintext secrets (phase 2); the tools that trigger the lazy load and the stdio smoke test that relies on it (phase 3). Stores for other platforms: TODO, no phase assigned.

## Context

This record answers the "Credential theft" row of "Security design at a glance" in README.md. A token file on disk can be read by other programs running as the user, for example a community Gmail MCP server, and the tokens in it give access to the mailbox within the granted scopes. The server should therefore write no plaintext token or client secret to disk.

Secure secret storage is a platform feature, and it is the only platform-specific part of the server: Gmail calls, MCP handling and drafts are platform-neutral Rust. macOS has the Keychain; Linux and Windows have their own stores. This record was revised on 2026-11-23, before it was first merged: the first draft treated the whole product as macOS-only.

## Decision

- **OS credential store only.** Credentials (OAuth client id and secret, refresh token) are persisted only in the operating system's credential store, behind one small interface, in a single item that also holds the granted scopes (see 0002-two-layer-permission-model.md). Access tokens stay in memory only.
- **macOS first.** The macOS Keychain is the first store, through the `security-framework` crate used directly. Rejected: `keyring` 4.x, which is deprecated and split into `keyring-core` plus separate store crates (see 0004-dependency-policy-and-libraries.md).
- **Other platforms: TODO.** No store exists yet for Linux or Windows. Candidates, not evaluated: the Secret Service API on Linux and Credential Manager on Windows. Each needs its own record and a dependency review under 0004. Until then those builds compile a stub whose operations return a clear "no secure store for this platform yet" error. There is never a file fallback, because that would put a plaintext copy back on disk.
- **Lazy load.** Credentials load on the first tool call, not at startup, so `initialize` and `tools/list` work without a store and CI can smoke-test the protocol on Linux.
- **Fail closed.** Every tool call fails with a clear error if the store or the credentials are unavailable when it needs them.
- **Bring your own OAuth client.** No client id or secret is shipped in the repo. Rejected: a shipped secret, because it is extractable and would tie every user to one Google app.
- **One-time import.** `gmail-mcp auth` reads Google's client secret JSON once into the store, tells the user to delete the file, and never deletes it itself. Later `auth` runs, such as the upgrade to drafts, reuse the stored client.
- **Secrets out of logs.** Secrets use a newtype with a redacted `Debug`, and logs go to stderr only, through one module with static messages. This is a guard, not a proof: error text returned to the client does not pass through the log module and must not contain secrets either (SECURITY.md).

## Consequences

- **Platforms.** Today credentials can be held only on macOS. On other platforms the server builds and starts, and `initialize` and `tools/list` work, but `auth` and every tool call fail closed until a store exists for that platform. Everything except the store builds and tests on Linux CI (0012-ci-on-linux.md).
- **Setup cost.** Every user creates their own Google OAuth client.
- **Plaintext copy.** The downloaded client secret JSON stays on disk until the user deletes it.
- **Keychain prompts.** Locally built macOS binaries are ad-hoc signed, so macOS probably asks for Keychain access again after a rebuild (an unverified expectation). Release binaries (first release planned for phase 4) carry no stable signing identity either, so the same may follow an update (also unverified).
- **Token lifetime.** Refresh tokens of an OAuth app in "Testing" mode expire after 7 days. Publishing the consent screen as "In production" without Google's app verification avoids that, at the cost of Google's unverified-app warning (details: README, Honest limits).
- **Late failure.** A broken store setup shows up at the first tool call, not at startup.
- **Residual risk.** The guarantee is narrow: the server writes no plaintext token or client secret file. This record does not claim that the credential store stops other programs running as the same user from reading the item; that depends on the platform's access control. An attacker who already controls the user's account or the store is out of scope (SECURITY.md).

## What would change this decision

- A store implemented for another platform: add a record for that store; this record stays.
- A stable code-signing identity for macOS release binaries, which would probably end the update re-prompts described above. It would not help builds from source, which are signed locally.
- A platform with no usable secure store: reconsider whether to support it at all, rather than adding a file fallback.

## References

- Decision records: [0002-two-layer-permission-model.md](0002-two-layer-permission-model.md), [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md) (where credentials may be sent), [0004-dependency-policy-and-libraries.md](0004-dependency-policy-and-libraries.md), [0012-ci-on-linux.md](0012-ci-on-linux.md)
- Repo files: [README.md](../../README.md), [SECURITY.md](../../SECURITY.md), [CONTRIBUTING.md](../../CONTRIBUTING.md) (secrets and logging rules), [.github/PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md), [Cargo.toml](../../Cargo.toml) (print lints), [.gitignore](../../.gitignore), [docs/maintainers/releasing.md](../maintainers/releasing.md) (release signing)
