# 0012. CI runs on Linux; platform-specific code gets narrow jobs

- Status: Accepted (2026-11-23)
- Implementation: In place: every job in `ci.yml` and `security.yml` runs on Linux. Release builds run on macOS because they produce a macOS binary (`release.yml`). Planned (phase 2): a narrow macOS job for the macOS credential store, and the change detection that decides when it runs.

## Context

The server is not tied to one platform: Gmail calls, MCP handling and drafts are platform-neutral Rust, and only secret storage differs by platform (0006). The macOS Keychain store compiles only on macOS, so Linux CI never builds it. macOS runners are also the expensive ones: on a private repository a macOS minute costs about ten times a Linux minute (0011). Earlier drafts of the pipeline ran the whole test suite on macOS as well, first on every pull-request commit and then on main; both were dropped, because one small platform-specific module does not justify running everything there.

## Decision

- Every CI job, including the whole test suite, runs on Linux.
- Platform-specific code stays small and sits behind the credential-store interface (0006), so the rest of the crate builds and tests on Linux. On Linux, CI compiles the stub store and tests its fail-closed path.
- When the macOS store lands (phase 2), it gets its own narrow macOS job that runs only its tests, on pull requests that change that code, the manifests or the workflow, and on main. A store for another platform gets the same treatment when it exists.
- macOS is otherwise used only to build release binaries, because the universal macOS binary needs it. Linux and Windows release builds wait until a credential store exists there.
- Rejected: running the full suite on macOS as well, because it adds cost and no coverage for platform-neutral code.

## Consequences

- Linux jobs do not compile the macOS store, so a break in it is caught only by the narrow macOS job. Until that job exists (phase 2) there is no such code to break. Review must check that a change touching platform-specific code also triggers its job.
- The narrow job needs to know what a pull request changed (a small change-detection job on Linux, or a path filter). That is part of the phase 2 work, and the required-check pitfall from 0007 applies: `ci-success` counts a skipped job as passed.
- macOS spend is limited to the narrow job and release builds.
- A platform-specific bug outside the store (path or line-ending handling, for example) would not show up on macOS or Windows CI. Accepted for now: the code is platform-neutral by design.

## What would change this decision

- Platform-specific behavior spreading beyond the credential store, which would mean widening the narrow jobs.
- Release binaries for more platforms, which need build jobs on those platforms.

## References

- [0006-credentials-in-os-credential-store.md](0006-credentials-in-os-credential-store.md), [0007-supply-chain-posture.md](0007-supply-chain-posture.md), [0011-private-for-now.md](0011-private-for-now.md)
- Workflows: [ci.yml](../../.github/workflows/ci.yml), [release.yml](../../.github/workflows/release.yml)
