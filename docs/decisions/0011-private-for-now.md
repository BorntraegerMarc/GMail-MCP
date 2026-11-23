# 0011. Private for now; public-only checks are skipped, not removed

- Status: Accepted (2026-11-23)
- Implementation: In place: a `github.event.repository.private == false` condition on the dependency-review job (`ci.yml`), the CodeQL job (`security.yml`), the Scorecard job (`scorecard.yml`) and the attestation step (`release.yml`). Not yet exercised: no workflow has run at all, and none has run on a public repository.

## Context

The maintainer made the repository private on 2026-11-23 for the time being. Making it open source later is possible but has no date. The pipeline in 0007 was designed for a public repository, and parts of it rely on GitHub features that are free for public repositories and sold separately, or not offered, for private ones. According to the GitHub documentation read on 2026-11-23:

- Dependency review on a private repository needs GitHub Code Security or GitHub Advanced Security.
- The Scorecard action supports a private repository only with GitHub Advanced Security. CodeQL code scanning is documented as available for all public repositories; the private-repository terms were not checked.
- Whether build-provenance attestations are available for a private repository on this account's plan is not established (the page read does not say).
- Standard hosted runners are free on public repositories. On a private repository they are metered: GitHub Free includes $12 of compute a month, and a macOS runner costs $0.062 a minute against $0.006 for a 2-core Linux runner.

## Decision

- Jobs that need a public repository stay in the workflows and run only when `github.event.repository.private == false`: dependency review, CodeQL, Scorecard and the provenance attestation. They start running by themselves when the repository becomes public.
- `ci-success` counts a skipped job as passed, so the required check stays meaningful: everything that can run while private must still pass (format, clippy, tests, MSRV, docs, cargo-deny, zizmor), and the daily advisories check still runs.
- Rejected: deleting the affected jobs, because they would have to be rewritten and reviewed again when the repository opens. Rejected: leaving them to fail, because every pull request would be red.

## Consequences

- While private, parts of the posture in 0007 are absent: no code scanning, no dependency review, no Scorecard and no provenance on releases. Dependabot, cargo-deny, zizmor, pinned actions and the lockfile checks still apply.
- The skipped jobs have never run, so expect first-run fixes on the day the repository goes public. Whether the `private` field is present on scheduled events is unverified; if it were missing, those scheduled jobs would run and fail while private, which is noisy but visible.
- Cost: macOS jobs are metered while private. CI runs entirely on Linux and macOS is used only to build releases (0012-ci-on-linux.md), so the exposure is small.
- Some GitHub settings (secret scanning, push protection, private vulnerability reporting, rulesets) depend on visibility or plan. The maintainer checks them in GitHub, and this repository does not document them (0007).
- `README.md` and `SECURITY.md` are written for a public project and stay as they are for when it opens.

## What would change this decision

- Making the repository public: the conditions then pass without edits. Supersede or deprecate this record once the skipped jobs have run cleanly.
- Buying code security features for the private repository, which would let the skipped jobs run now.

## References

- [0007-supply-chain-posture.md](0007-supply-chain-posture.md)
- Workflows: [ci.yml](../../.github/workflows/ci.yml), [security.yml](../../.github/workflows/security.yml), [scorecard.yml](../../.github/workflows/scorecard.yml), [release.yml](../../.github/workflows/release.yml)
- GitHub: <https://docs.github.com/en/billing/concepts/product-billing/github-actions>, <https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review>
