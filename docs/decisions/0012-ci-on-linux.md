# 0012. CI runs on Linux; platform-specific code gets narrow jobs

- Status: Accepted (2026-11-23)
- Implementation: In place (phase 2). Every job in `ci.yml` and `security.yml` runs on Linux except `macos-store`, the narrow macOS job for the credential store: clippy, the Keychain tests on a throwaway keychain, and rustdoc. A Linux job, `changes`, enables it when a pull request touches `src/store`, its test, the manifests, the toolchain pin or `ci.yml`; main and manual runs always run it, and `ci-success` counts both jobs. Release builds run on macOS because they produce a macOS binary (`release.yml`). The stub store and its fail-closed path are tested on Linux (`tests/store_policy.rs`).

## Context

The server is not tied to one platform: Gmail calls and MCP handling are platform-neutral Rust, and only secret storage differs by platform (0006). The macOS Keychain store compiles only on macOS, so Linux CI never builds it. macOS runners are also the expensive ones: on a private repository a macOS minute costs about ten times a Linux minute (0011). Earlier drafts of the pipeline ran the whole test suite on macOS as well, first on every pull-request commit and then on main; both were dropped, because one small platform-specific module does not justify running everything there.

## Decision

- Every CI job, including the whole test suite, runs on Linux, except the narrow macOS job for the credential store below.
- Platform-specific code stays small and sits behind the credential-store interface (0006), so the rest of the crate builds and tests on Linux. On Linux, CI compiles the stub store and tests its fail-closed path.
- The macOS store has its own narrow macOS job that runs only what Linux cannot: the lints on that code, its tests and its docs. It runs on pull requests that change that code, the manifests, the toolchain pin or the workflow, and on main. A store for another platform gets the same treatment when it exists.
- macOS is otherwise used only to build release binaries, because the universal macOS binary needs it. Linux and Windows release builds wait until a credential store exists there.
- Rejected: running the full suite on macOS as well, because it adds cost and no coverage for platform-neutral code.

## Consequences

- Linux jobs do not compile the macOS store, so a break in it, a lint included, is caught only by the narrow macOS job. Review must check that a change touching platform-specific code also triggers its job: the paths are listed in the `changes` job.
- The narrow job needs to know what a pull request changed, which a small change-detection job on Linux (`changes`) works out from the diff. The required-check pitfall from 0007 applies: `ci-success` counts a skipped job as passed, which is why a path-filtered workflow was not used.
- macOS spend is limited to the narrow job and release builds.
- A platform-specific bug outside the store (path or line-ending handling, for example) would not show up on macOS or Windows CI. Accepted for now: the code is platform-neutral by design.

## What would change this decision

- Platform-specific behavior spreading beyond the credential store, which would mean widening the narrow jobs.
- Release binaries for more platforms, which need build jobs on those platforms.

## References

- [0006-credentials-in-os-credential-store.md](0006-credentials-in-os-credential-store.md), [0007-supply-chain-posture.md](0007-supply-chain-posture.md), [0011-private-for-now.md](0011-private-for-now.md)
- Workflows: [ci.yml](../../.github/workflows/ci.yml), [release.yml](../../.github/workflows/release.yml)
