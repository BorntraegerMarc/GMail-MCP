# 0007. Supply-chain posture for CI and releases

- Status: Accepted (2026-11-23)
- Implementation: The pipeline exists in the scaffold (files under References), but `release.yml` has not run yet, not even as a dry run (planned before the first release, phase 4), and the README's build-from-source advice is planned with the full README (phase 4). There are no dependencies yet, so the dependency checks have nothing to inspect until phases 1 to 3 add crates. Jobs that need a public repository are skipped while it is private (0011). The GitHub settings under Decision cannot be verified from this repository.

## Context

Supply chain is the first threat in the README's security table. [`0004-dependency-policy-and-libraries.md`](0004-dependency-policy-and-libraries.md) covers the crates the binary links; this record covers the pipeline that tests, builds and ships it.

The repository is meant to be public (it is private for now; see 0011) and ships binaries as GitHub releases, not on crates.io. Outside contributors can open pull requests that run workflows, third-party actions run inside the project's jobs, and users run what is published. A compromised workflow, action or release job could alter the binary or take the token that publishes it.

The finished server will hold a user's Gmail grant in the operating system's credential store, the macOS Keychain first ([`0006-credentials-in-os-credential-store.md`](0006-credentials-in-os-credential-store.md); planned, phases 2 and 3), so a tampered release would run with that access.

## Decision

- **Pinned actions, few third-party.** Every action is pinned to a full commit SHA with its version in a comment, so a moved or re-pointed tag cannot change which action code runs. Dependabot proposes the bumps. Only `Swatinem/rust-cache`, `EmbarkStudios/cargo-deny-action`, `zizmorcore/zizmor-action` and `ossf/scorecard-action` are third-party, because each runs code the project does not control inside its jobs. The rest are `actions/*` or `github/codeql-action`, and Rust comes from rustup.
- **Least privilege and workflow hygiene.** Workflows start with `permissions: {}` and each job asks only for what it needs, so in most jobs a compromised step can read the repository but not change it. No workflow uses a repository secret, and checkouts set `persist-credentials: false` so later steps do not inherit the checkout's token. There is no `pull_request_target` (it would give fork pull requests a privileged context) and no `${{ }}` expression inside a `run:` block (values go through `env:`), so event data such as a branch name is never interpolated into shell code. zizmor and CodeQL's Actions analysis check this.
- **Check timing.** CI runs on pull requests and on main only; every CI job runs on Linux (0012); the push to main checks the squash-merged result. Its cargo-deny job covers bans, licenses and sources; the advisories check depends on outside data, so it runs daily on a schedule instead and a newly published advisory cannot turn unrelated PRs red. CodeQL (Rust and Actions) runs on pull requests, main and weekly; Scorecard, an outside-in health check, runs on main and weekly. Dependency review, CodeQL and Scorecard need a public repository (or paid GitHub code security features), so they are skipped while the repository is private (0011).
- **One required check, no path filters.** `ci-success` is meant to be the single required status check, so rulesets do not have to name every job; it counts a skipped job as passed. No job uses path filters, because a required check that a filter skips stays pending and blocks the merge, so a docs-only change is not exempt from CI.
- **Tag-driven releases.** A release is a pushed `vX.Y.Z` tag. The first job fails unless the tag matches the `Cargo.toml` version, the commit is on main and `CHANGELOG.md` has notes for it, so a mistyped tag, an off-main commit or missing notes stops the run before anything is built.
- **Distribution.** Source plus attested GitHub releases only. `Cargo.toml` sets `publish = false`: a crates.io release can be yanked but not withdrawn, and a second distribution channel would be a second thing to defend.
- **Release build.** Both architectures are built with `--locked` on the pinned toolchain and with no build cache, because release artifacts must not depend on cached state. They ship as one universal binary. Only macOS binaries are built for now, because the credential store exists only there (0006).
- **Attest, then publish.** In the release workflow only the last job holds write permissions and the OIDC token, and it never runs cargo, so no dependency build script or proc macro executes next to them. It attests build provenance so users can verify which run built a download (skipped while the repository is private, 0011), then publishes through a draft after every asset is uploaded, so a release is complete before it can become immutable (a repository setting).
- **No auto-versioning tools.** release-plz and release-please are not used: their release PRs need a personal access token or GitHub App to trigger CI, which adds a broad credential the pipeline otherwise does not have.
- **Dependabot cooldown.** Dependabot (Cargo and Actions) waits before proposing a new release, longer for major Cargo versions, so a compromised publish has time to surface. The `rust-toolchain` entry has a cooldown configured too, but Dependabot currently ignores it for that ecosystem. Security updates are exempt, and nothing is auto-merged.
- **Toolchain.** `rust-toolchain.toml` pins an exact stable compiler, so a new compiler release cannot change CI or release builds without a reviewed commit. Bumps arrive as Dependabot `rust-toolchain` pull requests that CI builds and the maintainer merges. Runner images are not pinned, so builds are not claimed to be reproducible.
- **Binaries.** Releases carry no Developer ID signature and are not notarized: the project has no signing identity and the workflow has no signing step (at most the linker's automatic ad-hoc signature is present). Building from source is the recommended way to audit before trusting a binary.
- **Settings stay outside the repository.** Rulesets (including one for `v*` tags), the Actions policy (an allowlist of permitted actions, SHA-pin enforcement), secret scanning and immutable releases are applied by the maintainer in GitHub. The click-through steps are intentionally not kept in the repository, and this design assumes the settings are in force.

## Consequences

- **Contributor friction.** Every action change needs a full-SHA pin with a version comment, and a new third-party action also needs the maintainer to allow it in the repository's Actions settings. `CONTRIBUTING.md` lists `.github/workflows/` among the files that get extra scrutiny.
- **Manual steps.** Every Dependabot PR needs a human because nothing is auto-merged, and the cooldown delays non-security updates (`docs/maintainers/releasing.md` lists the recurring chores). Checking that CI passed before tagging is manual too, because the release workflow does not do it.
- **Advisory timing.** A new advisory is flagged by the daily scheduled run, not at merge time, and dependency review covers only what a pull request adds or bumps. This relies on GitHub running the schedule (it can delay runs, and it disables schedules in public repositories after 60 days without activity) and on someone noticing a failed run.
- **Pins and attestations do not vouch for code.** A malicious version that is already pinned keeps running until someone notices; the cooldown and a human merging every bump reduce that exposure without removing it. The attestation records which run built an archive (the publish job attests whatever the build job uploaded), not that the source was benign. Scorecard is the one job where a third-party action runs with write-level permissions, because publishing its results needs them.
- **One maintainer.** There is no second reviewer. These controls limit what dependencies, actions and contributors can do in the pipeline, not what a compromised maintainer account can do, and a GitHub setting cannot be reviewed in a pull request or fail CI when it drifts.

## What would change this decision

- A trusted publishing option for the release flow, if one becomes available for how this project ships (GitHub releases, not a registry).
- Adopting a signing identity, so releases could be signed and notarized.
- Contributors who need a merge queue (CI would need a `merge_group` trigger).
- A way to run release-plz or release-please without a personal access token or GitHub App.

## References

- Decision records: [`0004-dependency-policy-and-libraries.md`](0004-dependency-policy-and-libraries.md), [`0006-credentials-in-os-credential-store.md`](0006-credentials-in-os-credential-store.md).
- Pipeline: [`ci.yml`](../../.github/workflows/ci.yml), [`security.yml`](../../.github/workflows/security.yml), [`scorecard.yml`](../../.github/workflows/scorecard.yml), [`release.yml`](../../.github/workflows/release.yml), [`dependabot.yml`](../../.github/dependabot.yml), [`rust-toolchain.toml`](../../rust-toolchain.toml), [`docs/maintainers/releasing.md`](../maintainers/releasing.md).
- Policy: [`README.md`](../../README.md), [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

