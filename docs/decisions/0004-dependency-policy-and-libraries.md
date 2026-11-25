# 0004. Dependency policy and library choices

- Status: Accepted (2026-11-23)
- Implementation: Partly in place. The policy and its guardrails exist: the `CONTRIBUTING.md` rules, `deny.toml` (the ban list and the single-`ureq` entry), `tests/deps_policy.rs` (the direct dependency allowlist), the committed `Cargo.lock`, Dependabot, the toolchain pin and the CI `msrv` job. Phase 1 added `ureq`, `oauth2` and, dev only, `proptest`, used by the egress guard and the output wrapper. `html2text` and `lettre` were planned and dropped (0013, 0014). Phase 2 added `security-framework` (macOS only, behind a target-specific table that `tests/deps_policy.rs` reads) and `serde_json`, which was already in the tree through `oauth2` and is used on `serde_json::Value` only, with no derive macros, so `serde` itself is not a direct dependency. The OAuth loopback listener is hand-written (`src/auth.rs`, 0015). Phase 3a added `base64` (pinned `=0.22.1`, the version `oauth2` uses; `ureq` uses 0.23, so the tree already held both and no crate was added; default features off, `std` only), used to decode Gmail's base64url bodies in `src/gmail.rs`. Planned: `rmcp`, `tokio` and, only if the tool macros need it, `serde` (phase 3b).

## Context

Supply chain is the first threat in the README's security table. In the planned server, every runtime dependency is compiled into the process that will hold the OAuth credentials and read the mail, so a compromised crate would have the same access as this project's own code. The maintainer's rule is that only official or very widely used crates are acceptable as direct dependencies. Avoiding dependencies is no way out: hand-rolling OAuth means more custom security code to audit, and there is one maintainer to audit it. The one exception so far is HTML-to-text, where the library proved unfit for hostile input (0013). CI and release hardening are in 0007.

## Decision

Use official or very widely used libraries for MCP, HTTP, OAuth and credential storage instead of hand-rolling them. (HTML conversion is hand-written, 0013; the server composes no mail, so there is no MIME library, 0014.) A new direct dependency must be official or very widely used and actively maintained, MIT or Apache-2.0 (or a compatible permissive license), exactly pinned as `=x.y.z` and justified in its PR (checklist: `CONTRIBUTING.md`). The exact pin keeps a direct dependency's version from moving without a visible `Cargo.toml` edit, even in a build that ignores the lockfile. `Cargo.lock` is committed and CI and release builds use `--locked`, so they resolve exactly the committed versions. Controls:

- `deny.toml` denies a named list of crates from the usual alternative HTTP/TLS stacks, any source but crates.io and non-permissive licenses. It cannot detect an unlisted HTTP client, and `multiple-versions` only warns. A per-crate `deny-multiple-versions = true` entry for `ureq` makes a second `ureq` major fail the bans check instead of being caught only by reading the `Cargo.lock` diff.
- `tests/deps_policy.rs` fails when the direct dependency list, a `default-features` setting or an enabled feature changes without updating its allowlist, so additions are visible in review. Version numbers are not compared, so Dependabot's bumps stay mergeable. Only review judges whether a crate is official or very widely used and whether it is pinned with `=` (`wildcards = "deny"` rejects only wildcard requirements); the PR template has the author attest to both.
- Dependabot (Cargo and GitHub Actions) waits out a cooldown after each release so a compromised publish can surface, at the price of adopting releases days late; security updates skip it. Nothing is auto-merged.

Chosen libraries (versions as measured on 2026-11-23; `Cargo.toml` will hold the exact pins):

| Library | Reason |
|---|---|
| `rmcp` 3.11 | Official MCP Rust SDK; runs on tokio |
| `tokio`, `serde`, `serde_json` | The runtime `rmcp` runs on; JSON for MCP and the Gmail API |
| `ureq` 3 (blocking, rustls) | The only HTTP client: blocking, so no async runtime in the HTTP path (0008); TLS comes from rustls |
| `oauth2` 5 | PKCE, auth URL, code exchange and refresh; the crate `rmcp` itself uses for OAuth |
| `base64` | Gmail's base64url encoding of message bodies |
| `security-framework` (macOS only) | The macOS Keychain store, used directly instead of `keyring` (0006); stores for other platforms are TODO |
| `proptest` (dev only) | Property tests for untrusted-input handling |

- Rejected: `google-gmail1` (community-generated, brings a hyper plus tokio stack and exposes every send and delete method, defeating a minimal surface); `keyring` 4.x (reason in 0006); `reqwest` and `hyper` (a second HTTP stack); `oauth2`'s built-in `ureq` feature (reason and replacement in 0003); hand-rolled OAuth (see Context); `html2text` (it panics on 40-byte inputs, and its run time and output grow with nesting depth: 0013); `lettre` and any other MIME library (the server composes no mail: 0014).
- Hand-written: the egress guard, the output wrapping and sanitizer and the HTML-to-text converter (0003, 0005, 0013), which encode this project's own rules or replace a library that proved unfit, and the OAuth loopback listener (about 140 lines with its request parsing and its answer page, 0015), too small to justify a dependency under the policy's "why a small amount of code would not do" test.
- Toolchain (as of 2026-11-23): the compiler pin (`rust-toolchain.toml`) and its Dependabot-driven bumps are in 0007. `rust-version` (the MSRV) is 1.89, the highest minimum in the measured tree (`uuid`, via `rmcp`), and the CI `msrv` job checks the code with exactly that version.

## Consequences

- Measured on 2026-11-23 in a throwaway project: the tree is 161 unique crates (the dev-only `proptest` is not itemized). `rmcp` plus `tokio` alone are 72; `oauth2` adds 19, `html2text` 16, `ureq` 12, `lettre` 8, `security-framework` 4. No banned crate is present and all licenses are permissive. That is larger than a hand-rolled approach would be, accepted for less custom security code to audit. (`html2text` and `lettre` are no longer planned, 0013 and 0014, so the final tree should be about 24 crates smaller.)
- Measured on 2026-11-24 with the libraries now in use (`ureq`, `oauth2`): 82 unique crates in the normal tree, 92 with `proptest` (limited to its `std` feature), none of them banned. About two thirds of the normal tree come in through `oauth2`, mostly `url` and its internationalised-domain stack (the ICU crates).
- Measured on 2026-11-24 after phase 2: still 82 unique crates in the normal tree on Linux, because `serde_json` was already there through `oauth2`. The macOS build adds 5 (`security-framework`, `security-framework-sys`, `core-foundation`, `core-foundation-sys` and `bitflags`), 87 in total, all MIT or Apache-2.0. No banned crate is present.
- The "official or very widely used" test gates all direct dependencies (the eight runtime ones plus dev-only `proptest`). The other 120 or so crates are not vetted one by one; `Cargo.lock`, cargo-deny (bans, licenses and sources on every PR, advisories daily) and dependency review limit them.
- A compromised dependency runs in the same process, so this project's own guards (egress guard, static tests, tool list) do not bind it: it could use the credentials and contact any host. Only the Google-side scope still bounds what it can do to the mailbox: `gmail.readonly` cannot write (0014), though the dependency could still read mail and send it elsewhere.
- `html2text` was the most debatable choice and did not survive review: the named fallback, a small hand-written converter, replaced it (0013).
- `cargo install` ignores `Cargo.lock` without `--locked`, so the build-from-source instructions (phase 4) must pass it.
- Upkeep is manual and falls on one person: reviewing Dependabot's PRs, toolchain bumps included, and keeping `rust-version` equal to the highest minimum in the tree, which a Cargo dependency update can raise.

## What would change this decision

- Tree growth: if the real tree ends up well above the measured size (each dependency PR reports how many crates it adds), re-weigh the biggest shares first: `rmcp` with `tokio`, then `oauth2` with its `url` stack. `oauth2` stays while hand-rolled OAuth stays rejected.
- A library losing maintenance (no fixes, or deprecation as with `keyring` 4.x, 0006): replace it or reconsider hand-writing what it covered.
- A major `rmcp` release: the MSRV and the `oauth2` choice both follow `rmcp`, so a new minimum Rust version, dependency set or OAuth crate reopens both.

## References

- Decision records: [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md), [0005-untrusted-email-content.md](0005-untrusted-email-content.md), [0006-credentials-in-os-credential-store.md](0006-credentials-in-os-credential-store.md), [0007-supply-chain-posture.md](0007-supply-chain-posture.md), [0013-hand-written-html-converter.md](0013-hand-written-html-converter.md), [0014-read-only-no-composing.md](0014-read-only-no-composing.md)
- Repo files: [README.md](../../README.md), [CONTRIBUTING.md](../../CONTRIBUTING.md), [deny.toml](../../deny.toml), [Cargo.toml](../../Cargo.toml), [rust-toolchain.toml](../../rust-toolchain.toml), [.github/dependabot.yml](../../.github/dependabot.yml), [.github/PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md), [.github/workflows/ci.yml](../../.github/workflows/ci.yml), [.github/workflows/security.yml](../../.github/workflows/security.yml), [.github/workflows/release.yml](../../.github/workflows/release.yml), [docs/maintainers/releasing.md](../maintainers/releasing.md)

