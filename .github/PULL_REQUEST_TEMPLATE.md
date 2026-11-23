## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Security impact

<!-- Required. "None" is a fine answer if it is true. -->

- [ ] This PR does **not** add or widen any capability: no new Gmail endpoint, HTTP method, OAuth scope, allowed host, tool, or tool parameter.
- [ ] If it does, I explained why above and updated the egress allowlist, `tests/static_policy.rs` and the README threat model.
- [ ] This PR does **not** add a dependency. If it does, it is official or very widely used, MIT/Apache-licensed, pinned with `=`, and justified above (see CONTRIBUTING.md).
- [ ] No secrets, tokens, real email content or personal data in code, tests, fixtures or logs.

## Checks

- [ ] `cargo fmt --all --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`
- [ ] `CHANGELOG.md` updated under **Unreleased** (user-visible changes)
- [ ] Tests added or updated
- [ ] Parts of this change were written with an AI assistant (disclosure only; the same review bar applies)
