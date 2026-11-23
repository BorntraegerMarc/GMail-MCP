# Contributing

Thanks for helping. This project's value is that it is **small and hard to abuse**, so the rules below are stricter than usual.

## Ground rules

1. **No new write capability, ever.** The server must never send, forward, delete, trash, mark as spam, change labels, filters or settings. The only Gmail write is creating a draft, and only when started with `--allow-drafts`. Pull requests that add any of these will be closed.
2. **Any change to what the server can do needs a security note** in the PR: a new tool or tool parameter, Gmail endpoint, HTTP method, OAuth scope, or allowed host. It must update the egress allowlist, `tests/static_policy.rs` and the README threat model in the same PR.
3. **Secrets never enter the repo or the logs.** No tokens, client secrets, real email content or addresses in code, tests, fixtures, issues or PRs.
4. **No panics on untrusted input.** Production code does not `unwrap`/`expect`; clippy enforces this. Email content, headers and API responses are untrusted.
5. **stdout belongs to the MCP protocol.** Nothing prints to stdout. All logging goes through one module to stderr and never contains tokens, subjects, bodies or addresses.

## Dependency policy

A new direct dependency must be:

- **official or very widely used** and actively maintained,
- licensed MIT or Apache-2.0 (or compatible permissive),
- pinned with an exact version (`=x.y.z`) in `Cargo.toml`, with `Cargo.lock` committed,
- justified in the PR description: what it replaces, how many crates it adds (`cargo tree`), and why a small amount of code would not do.

`deny.toml` bans a second HTTP/TLS stack (`reqwest`, `hyper`, `openssl`, `native-tls`, `curl`, ...) and unknown registries; `tests/deps_policy.rs` (added with the first dependencies) fails when the direct dependency list changes without updating its allowlist, so additions are always visible in review. Dependabot proposes updates weekly with a cooldown; none are auto-merged.

## Security-critical files

Review these with extra care, and expect extra scrutiny of changes to them: `src/http.rs` (the only network egress), `src/policy.rs`, `src/auth.rs`, `src/keychain.rs`, `src/draft.rs`, `src/tools.rs`, `deny.toml`, `.github/workflows/`, and everything under `tests/`.

## Local checks

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo deny check bans licenses sources    # optional locally: brew install cargo-deny
```

CI runs the same checks plus MSRV, docs, `zizmor` (workflow security lint), dependency review, CodeQL and OpenSSF Scorecard.

## Pull requests

- Keep them small and focused; one concern per PR.
- Update `CHANGELOG.md` under **Unreleased** for user-visible changes.
- Squash merge only; the PR title becomes the commit message.
- Changes written with an AI assistant are welcome and are held to the same standard. Please say so in the PR.

## Reporting vulnerabilities

Privately, via [SECURITY.md](SECURITY.md). Never in a public issue.
