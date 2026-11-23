# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Added

- Repository scaffold: stub crate, CI (fmt, clippy, tests, MSRV, docs, cargo-deny, zizmor,
  dependency review), CodeQL, OpenSSF Scorecard, release workflow with build-provenance
  attestation, Dependabot, security policy, contribution guide, agent instructions
  (`AGENTS.md`, imported by `CLAUDE.md`) and decision records in `docs/decisions/`.
- Pipeline jobs that need a public repository (dependency review, CodeQL, Scorecard, release attestation) are skipped while the repository is private.
