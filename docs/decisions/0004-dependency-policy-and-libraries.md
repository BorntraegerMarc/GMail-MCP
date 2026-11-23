# 0004. Dependency policy and library choices

- Status: Accepted (2026-11-23)
- Implementation: The policy and its guardrails exist today (the `CONTRIBUTING.md` rules, `deny.toml`, the committed `Cargo.lock`, Dependabot, the toolchain pin, the CI `msrv` job). `Cargo.toml` has no dependencies yet, so nothing below about libraries, tests or modules exists in code. Planned: each library arrives with the phase that first uses it (`security-framework` in phase 2, `rmcp` in phase 3); phase 1 adds `tests/deps_policy.rs`, a `deny.toml` entry denying multiple `ureq` versions, the egress guard and the output sanitizer; phase 2 adds the OAuth loopback listener.

## Context

Supply chain is the first threat in the README's security table. In the planned server, every runtime dependency is compiled into the process that will hold the OAuth credentials and read the mail, so a compromised crate would have the same access as this project's own code. The maintainer's rule is that only official or very widely used crates are acceptable as direct dependencies. Avoiding dependencies is no way out: hand-rolling OAuth, MIME and HTML parsing means more custom security code to audit, and there is one maintainer to audit it. CI and release hardening are in 0007.

## Decision

Use official or very widely used libraries for MCP, HTTP, OAuth, MIME, HTML conversion and credential storage instead of hand-rolling them. A new direct dependency must be official or very widely used and actively maintained, MIT or Apache-2.0 (or a compatible permissive license), exactly pinned as `=x.y.z` and justified in its PR (checklist: `CONTRIBUTING.md`). The exact pin keeps a direct dependency's version from moving without a visible `Cargo.toml` edit, even in a build that ignores the lockfile. `Cargo.lock` is committed and CI and release builds use `--locked`, so they resolve exactly the committed versions. Controls:

- `deny.toml` denies a named list of crates from the usual alternative HTTP/TLS stacks, any source but crates.io and non-permissive licenses. It cannot detect an unlisted HTTP client, and `multiple-versions` only warns. Planned in phase 1, with `ureq`: a per-crate `deny-multiple-versions = true` entry, so a second `ureq` major fails the bans check instead of being caught only by reading the `Cargo.lock` diff.
- The planned `tests/deps_policy.rs` fails when the direct dependency list changes without updating its allowlist, so additions are visible in review. Only review judges whether a crate is official or very widely used and whether it is pinned with `=` (`wildcards = "deny"` rejects only wildcard requirements); the PR template has the author attest to both.
- Dependabot (Cargo and GitHub Actions) waits out a cooldown after each release so a compromised publish can surface, at the price of adopting releases days late; security updates skip it. Nothing is auto-merged.

Chosen libraries (versions as measured on 2026-11-23; `Cargo.toml` will hold the exact pins):

| Library | Reason |
|---|---|
| `rmcp` 3.11 | Official MCP Rust SDK; runs on tokio |
| `tokio`, `serde`, `serde_json` | The runtime `rmcp` runs on; JSON for MCP and the Gmail API |
| `ureq` 3 (blocking, rustls) | The only HTTP client: blocking, so no async runtime in the HTTP path (0008); TLS comes from rustls |
| `oauth2` 5 | PKCE, auth URL, code exchange and refresh; the crate `rmcp` itself uses for OAuth |
| `lettre` 0.11 (builder only) | MIME drafts with strict address parsing; nothing is ever sent, so no SMTP transport |
| `html2text` | HTML-only mail to text instead of hand-rolled parsing |
| `base64` | Gmail's base64url encoding of bodies and drafts |
| `security-framework` (macOS only) | The macOS Keychain store, used directly instead of `keyring` (0006); stores for other platforms are TODO |
| `proptest` (dev only) | Property tests for untrusted-input handling |

- Rejected: `google-gmail1` (community-generated, brings a hyper plus tokio stack and exposes every send and delete method, defeating a minimal surface); `keyring` 4.x (reason in 0006); `reqwest` and `hyper` (a second HTTP stack); `oauth2`'s built-in `ureq` feature (reason and replacement in 0003); hand-rolled OAuth and MIME (see Context).
- Hand-written: the egress guard and the output wrapping and sanitizer (0003, 0005), which encode this project's own rules, and the OAuth loopback listener, expected to be about 40 lines, too small to justify a dependency under the policy's "why a small amount of code would not do" test.
- Toolchain (as of 2026-11-23): the compiler pin (`rust-toolchain.toml`) and its Dependabot-driven bumps are in 0007. `rust-version` (the MSRV) is 1.89, the highest minimum in the measured tree (`uuid`, via `rmcp`), and the CI `msrv` job checks the code with exactly that version.

## Consequences

- Measured on 2026-11-23 in a throwaway project: the tree is 161 unique crates (the dev-only `proptest` is not itemized). `rmcp` plus `tokio` alone are 72; `oauth2` adds 19, `html2text` 16, `ureq` 12, `lettre` 8, `security-framework` 4. No banned crate is present and all licenses are permissive. That is larger than a hand-rolled approach would be, accepted for less custom security code to audit.
- The "official or very widely used" test gates all direct dependencies (the ten runtime ones plus dev-only `proptest`). The other 150 or so crates are not vetted one by one; `Cargo.lock`, cargo-deny (bans, licenses and sources on every PR, advisories daily) and dependency review limit them.
- A compromised dependency runs in the same process, so this project's own guards (egress guard, static tests, no-send rule, tool list) do not bind it: it could use the credentials and contact any host. Only the Google-side scope still bounds it: read-only by default, and with `--allow-drafts` `gmail.compose` also permits sending at the API level.
- `html2text` is the most debatable choice: it serves only the exception of HTML-only mail (text/plain is preferred). The named fallback, a small hand-written stripper, trades its crates for custom code that handles hostile input.
- `cargo install` ignores `Cargo.lock` without `--locked`, so the build-from-source instructions (phase 4) must pass it.
- Upkeep is manual and falls on one person: reviewing Dependabot's PRs, toolchain bumps included, and keeping `rust-version` equal to the highest minimum in the tree, which a Cargo dependency update can raise.

## What would change this decision

- Tree growth: if the real tree ends up well above the measured 161 crates (each dependency PR reports how many crates it adds), re-weigh `html2text` first, the only library with a named hand-written fallback. `oauth2` and `lettre` stay while hand-rolled OAuth and MIME stay rejected.
- A library losing maintenance (no fixes, or deprecation as with `keyring` 4.x, 0006): replace it or reconsider hand-writing what it covered.
- A major `rmcp` release: the MSRV and the `oauth2` choice both follow `rmcp`, so a new minimum Rust version, dependency set or OAuth crate reopens both.

## References

- Decision records: [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md), [0005-untrusted-email-content.md](0005-untrusted-email-content.md), [0006-credentials-in-os-credential-store.md](0006-credentials-in-os-credential-store.md), [0007-supply-chain-posture.md](0007-supply-chain-posture.md)
- Repo files: [README.md](../../README.md), [CONTRIBUTING.md](../../CONTRIBUTING.md), [deny.toml](../../deny.toml), [Cargo.toml](../../Cargo.toml), [rust-toolchain.toml](../../rust-toolchain.toml), [.github/dependabot.yml](../../.github/dependabot.yml), [.github/PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md), [.github/workflows/ci.yml](../../.github/workflows/ci.yml), [.github/workflows/security.yml](../../.github/workflows/security.yml), [.github/workflows/release.yml](../../.github/workflows/release.yml), [docs/maintainers/releasing.md](../maintainers/releasing.md)

