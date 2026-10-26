# Contributing to nuvek-core

Thanks for taking the time to help. Bug reports, ideas, documentation fixes and code are all
welcome. This guide says how to get a change from an idea to a merged pull request.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

**Security problems are not reported in issues.** Follow [SECURITY.md](SECURITY.md) and use
GitHub's private vulnerability reporting.

## Reporting a bug

[Open a bug report](https://github.com/jean1880/nuvek-core/issues/new?template=bug_report.yml).
Search the [open and closed issues](https://github.com/jean1880/nuvek-core/issues?q=is%3Aissue)
first, and try `master`, where fixes land before a release.

**Review everything you paste for secrets.** Logs and configuration can hold API keys, tokens,
hostnames and file paths. Replace anything sensitive with `****` before you post.

## Before you write code

**Open an issue first for anything bigger than a small fix**: a new feature, a new module, a
change of behaviour or a new dependency. A short discussion up front avoids a pull request that
cannot be merged as written. Typo fixes, small documentation fixes and obvious bug fixes can go
straight to a pull request.

The rules that most often decide a review:

- **nuvek-core is mechanism.** It never names a host, a path, a person, or a product beyond the
  protocol it speaks. If a value would differ on someone else's machine, it is a parameter the
  caller supplies, not a constant here.
- **A module with one consumer belongs in that consumer.** "Several tools might need it" is not
  enough to add it here.
- **Every Cargo feature gates a module**, and each feature must build on its own
  (`cargo check -p nuvek-core --no-default-features --features <f>`).
- **Fail closed on a security boundary.** A secret scan or a read-only guard that cannot decide
  answers "unsafe", never "safe". Secret surfaces are only ever added, never removed.
- **No `unwrap`, `expect` or `panic!` in library code.** Tests may use them.
- **Strings are sliced by character, never by byte.** Guard every slice with a multi-byte test.
- **Every external call is bounded by a timeout.**
- **Tests never touch real `$HOME` state.** Use a temporary directory.

## Setting up

You need Rust 1.90 or newer.

```bash
git clone https://github.com/jean1880/nuvek-core.git
cd nuvek-core
git config core.hooksPath .githooks   # gitleaks and rustfmt before each commit
```

The pre-commit hook needs [gitleaks](https://github.com/gitleaks/gitleaks) on your `PATH`.

## Testing

What CI runs, and what to run before you push:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps
cargo deny check licenses bans sources
```

Tests that need a live ChromaDB, Neo4j or Ollama are skipped unless `NUVEK_LIVE_TESTS=1`.

- **A bug fix** comes with a test that fails without the fix.
- **New logic** comes with unit tests beside it.
- **A change to a secret pattern or surface** comes with tests for what it must catch and for
  ordinary text it must leave alone.

## Commits

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
fix(scrub): match .env.local as a secret surface
feat(ssh): add exec_stdin with a bounded write
```

- **Types**: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `style`.
- **Subject**: says what is now true, in lower case, without a full stop.
- **Body**: explains why, when the subject alone doesn't. Mention a breaking change as
  `BREAKING CHANGE:` in the footer.
- **Sign off every commit** (`git commit -s`). The `Signed-off-by:` line certifies the
  [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the change
  or otherwise have the right to submit it under the project's licence. Pull requests with
  unsigned commits are not merged.

Write prose in Canadian English (colour, behaviour, centre, licence as a noun). Code identifiers
keep their own spelling.

## Pull requests

1. Run the checks above and make sure they pass.
2. Open the pull request against `master`. Its title follows the Conventional Commits format.
3. Link the issue with `Fixes #123`, so it closes on merge.
4. Add an entry to the crate's `CHANGELOG.md` for anything a user of the crate would notice.

Releases are cut by the maintainer. Leave the versions in `Cargo.toml` alone.

## AI-assisted contributions

Using AI tools in a contribution is fine. The responsibility for it stays with you: say so in the
pull request, understand every line, and run the checks yourself.

## Licence

nuvek-core is released under the [MIT Licence](LICENSE). By contributing, you agree that your
contribution is licensed under the same terms, and you certify the Developer Certificate of Origin
with your `Signed-off-by:` line.
