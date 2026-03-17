# Contributing to Neural Commons

Thanks for your interest in contributing. This project handles security-sensitive
infrastructure, so we hold contributions to a high standard. That said, we
welcome patches of all sizes — from typo fixes to new features.

## Quick start

You will need Rust 1.85+ (edition 2024).

```bash
git clone https://github.com/LCatGA12/neural-commons.git
cd neural-commons
cargo build --workspace
cargo test --workspace
```

The workspace currently contains two top-level crates (`adapter/` and
`cluster/`) plus shared libraries (`aegis-crypto`, `aegis-schemas`). The
`cluster/` workspace is scaffolded but not yet active.

All 461+ tests must pass before you submit a PR.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes. Write tests for new functionality.
3. Run the full check suite locally:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```
4. Push your branch and open a PR against `main`.

CI runs automatically on every push to `main` and on PRs. The pipeline
includes: check, test, contract tests, build, end-to-end smoke test, and
security audit. Your PR will not be merged until CI is green.

### PR labels and versioning

The project uses auto-release on merge to `main`. The default version bump is
**patch**. Use these PR labels to control it:

- `release:skip` — no version bump
- `release:minor` — minor version bump
- `release:major` — major version bump

## Code style

- Format with `cargo fmt`. No exceptions.
- `cargo clippy --workspace -- -D warnings` must produce zero warnings.
- Keep functions short. Prefer clarity over cleverness.
- No `unsafe` without a comment explaining why it is necessary and safe.

## Commit messages

Use conventional commit style:

```
feat: add TLS certificate rotation
fix: handle empty payload in proxy handler
docs: clarify adapter configuration options
test: add coverage for token refresh edge case
```

Keep the subject line under 72 characters. Use the body for context when the
change is not obvious. Reference related issues with `Closes #123` or
`Refs #456`.

## Testing

- All existing tests must pass (`cargo test --workspace`).
- New features require tests. Bug fixes should include a regression test.
- If your change touches `aegis-crypto` or `aegis-schemas`, verify that
  downstream crates still compile and pass tests.
- Integration and contract tests are part of CI. If you add a new external
  interface, add corresponding contract tests.

## Before you start large changes

Open an issue first. Describe what you want to change and why. This avoids
wasted effort if the change conflicts with the project's direction or if
someone is already working on it.

For security-related issues, do **not** open a public issue. Contact the
maintainers directly.

## License

This project is licensed under AGPL-3.0-or-later. By submitting a pull
request, you agree that your contributions will be licensed under the same
terms. See [LICENSE](LICENSE) for details.
