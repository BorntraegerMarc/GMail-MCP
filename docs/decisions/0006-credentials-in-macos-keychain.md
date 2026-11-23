# 0006. Credentials only in the macOS Keychain, fail closed

- Status: Accepted (2026-11-23)
- Implementation: Not implemented yet. Guardrails today include the `.gitignore` entries for credential-like file names, the clippy print lints in `Cargo.toml`, and the secrets rules in CONTRIBUTING.md and the PR template. Planned: the log module (phase 1); Keychain storage with lazy load and fail-closed errors, the non-macOS stub, `gmail-mcp auth`, the secret type and a script that scans for plaintext secrets (phase 2); the tools that trigger the lazy load and the stdio smoke test that relies on it (phase 3).

## Context

This record answers the "Credential theft" row of "Security design at a glance" in README.md. A token file on disk can be read by other programs running as the user, for example a community Gmail MCP server, and the tokens in it give access to the mailbox within the granted scopes. The server should therefore write no plaintext token or client secret to disk.

## Decision

- **Keychain only.** Credentials (OAuth client id and secret, refresh token) will be persisted only in the macOS Keychain, in a single item that also holds the granted scopes (see 0002-two-layer-permission-model.md). Access tokens will stay in memory only.
- **Library.** The `security-framework` crate will be used directly. Rejected: `keyring` 4.x, which is deprecated and split into `keyring-core` plus separate store crates (see 0004-dependency-policy-and-libraries.md).
- **Other platforms.** Non-macOS builds will compile a stub that errors instead of offering another storage path.
- **Lazy load.** Credentials will load on the first tool call, not at startup, so `initialize` and `tools/list` work without a Keychain and CI can smoke-test the protocol.
- **Fail closed.** Every tool call will fail with a clear error if the Keychain or the credentials are unavailable when it needs them. There will be no file fallback, because that would put a plaintext copy back on disk.
- **Bring your own OAuth client.** No client id or secret will be shipped in the repo. Rejected: a shipped secret, because it is extractable and would tie every user to one Google app.
- **One-time import.** `gmail-mcp auth` will read Google's client secret JSON once into the Keychain, tell the user to delete the file, and never delete it itself. Later `auth` runs, such as the upgrade to drafts, will reuse the stored client.
- **Secrets out of logs.** Secrets will use a newtype with a redacted `Debug`, and logs will go to stderr only, through one module with static messages. This is a guard, not a proof: error text returned to the client does not pass through the log module and must not contain secrets either (SECURITY.md).

## Consequences

- **macOS only.** Users on other platforms will not be able to use the tools.
- **Setup cost.** Every user will have to create their own Google OAuth client.
- **Plaintext copy.** The downloaded client secret JSON stays on disk until the user deletes it.
- **Keychain prompts.** Locally built binaries are ad-hoc signed, so macOS probably asks for Keychain access again after a rebuild (an unverified expectation). Release binaries (first release planned for phase 4) will carry no stable signing identity either, so the same may follow an update (also unverified).
- **Token lifetime.** Refresh tokens of an OAuth app in "Testing" mode expire after 7 days. Publishing the consent screen as "In production" without Google's app verification avoids that, at the cost of Google's unverified-app warning (details: README, Honest limits).
- **Late failure.** A broken Keychain setup will show up at the first tool call, not at startup.
- **Residual risk.** The guarantee is narrow: the server will write no plaintext token or client secret file. This record does not claim that the Keychain stops other programs running as the same user from reading the item; that depends on macOS access control. An attacker who already controls the user's account or the Keychain is out of scope (SECURITY.md).

## What would change this decision

- Linux support, which would need its own decision record for a secret store.
- A stable code-signing identity for release binaries, which would probably end the update re-prompts described above. It would not help builds from source, which are signed locally.

## References

- Decision records: [0002-two-layer-permission-model.md](0002-two-layer-permission-model.md), [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md) (where credentials may be sent), [0004-dependency-policy-and-libraries.md](0004-dependency-policy-and-libraries.md)
- Repo files: [README.md](../../README.md), [SECURITY.md](../../SECURITY.md), [CONTRIBUTING.md](../../CONTRIBUTING.md) (secrets and logging rules), [.github/PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md), [Cargo.toml](../../Cargo.toml) (print lints), [.gitignore](../../.gitignore), [docs/maintainers/releasing.md](../maintainers/releasing.md) (release signing)

