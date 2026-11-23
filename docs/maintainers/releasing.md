# Releasing

Releases are tag-driven. Pushing a tag `vX.Y.Z` runs [`release.yml`](../../.github/workflows/release.yml), which builds a universal macOS binary, attests its build provenance, and publishes a GitHub release.

## Cut a release

1. **Release PR** (a normal PR, squash-merged):
   - Bump `version` in `Cargo.toml` to `X.Y.Z` and refresh `Cargo.lock` (`cargo check --locked` fails if it is stale; run `cargo update -p gmail-mcp --offline`).
   - In `CHANGELOG.md`, rename **Unreleased** to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty **Unreleased** section above it.
2. **Tag `main`** after the PR has merged and CI is green:

   ```bash
   git switch main && git pull --ff-only
   git tag -s vX.Y.Z -m "vX.Y.Z"   # drop -s if you do not sign tags
   git push origin vX.Y.Z
   ```

   Only the maintainer may create `v*` tags (enforced by a tag ruleset on the repository).
3. **Watch the run.** The workflow refuses to publish unless the tag matches `Cargo.toml`, the tagged commit is on `main`, and `CHANGELOG.md` has a non-empty section for the version. It then creates a *draft* release, uploads the assets, and publishes it (the order GitHub recommends, so an immutable release is complete the moment it becomes immutable).

## Dry run

**Actions → Release → Run workflow** builds the universal binary and uploads it as a workflow artifact, without attesting or publishing. Use it before the first release and after touching the workflow.

## What consumers can verify

```bash
gh attestation verify gmail-mcp-X.Y.Z-macos-universal.tar.gz --repo BorntraegerMarc/GMail-MCP
shasum -a 256 -c SHA256SUMS
```

The full README (planned, phase 4) will recommend building from source for anyone who wants to audit first. Release binaries are not signed with an identity and not notarized; at most the linker's automatic ad-hoc signature is present (checked on 2026-11-23 for the arm64 slice only). macOS may therefore ask for Keychain access again after an update; that is an expectation, not something verified.

## Recurring chores

- Review Dependabot's `rust-toolchain` PRs (they bump `channel` in `rust-toolchain.toml`; version updates only, and Dependabot currently ignores the cooldown for this ecosystem).
- After merging a Dependabot Cargo PR, check that `rust-version` in `Cargo.toml` still matches the highest requirement in the dependency tree; an update can raise it.
- Skim open Dependabot PRs and the Security tab.
