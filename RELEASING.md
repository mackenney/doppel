# Releasing doppel

`doppel` and `doppel-cli` share one version and release together with
`cargo-release` (`release.toml`). Preparation is not authorization to publish:
`--execute` uploads to crates.io, tags and pushes, and cannot be undone.

## Conventions

- Version source of truth: `version` in `doppel/Cargo.toml` and
  `doppel-cli/Cargo.toml`, kept equal. `doppel-cli` also pins `doppel` by
  `version`; `cargo-release` bumps it.
- Tag: `v<version>` (for example `v0.1.0`), created by the `doppel` crate, on the
  release commit `chore: release v<version>`. Tags are mandatory: every version
  published to crates.io MUST have its tag, and the tagged commit MUST be on
  `main`'s first-parent chain (the release commit itself or a merge into `main`),
  never a feature-branch commit. `0.0.1` predates this rule and is the only
  exception (`scripts/check-tags.sh`).
- Pre-1.0 semver: a minor bump (0.x.0) for breaking changes, a patch bump for
  fixes and additive changes.
- crates.io versions are immutable. Never move a published tag; to repair a bad
  release, yank the version and release a new one.
- Feature and preparation work lands on branches merged with `--no-ff`. Only
  the generated release commit is made directly on `main`.
- Origin fetches from SourceHut and pushes to both SourceHut and GitHub. Query
  both when checking tags.

## Checklist

1. Move finished plans to Completed in `MASTER_PROGRESS.md`.
2. CHANGELOG, strictly: `[Unreleased]` MUST list every user-visible change since
   the last tag (Added, Changed, Fixed, Documentation, Testing), flag behavior
   changes, and keep the `<!-- next-header -->` / `<!-- next-url -->` markers.
   Walk `git log --first-parent <last-tag>..main` and confirm each merge is
   covered. `just changelog-check` fails if the file is unchanged since the last
   tag, `[Unreleased]` is empty, or source changed with no Added/Changed/Fixed
   section.
3. Docs, strictly: README, `docs/` and SPEC.md MUST match current behavior. For
   every changed command or option, compare the docs against `doppel --help` and
   `doppel <command> --help`. `just docs-check` fails on any flag or charset that
   appears in the CLI help but not in the README CLI reference, or the reverse.
   Prose, examples and SPEC.md are not machine-checked: read them.
4. Merge to `main` with `--no-ff`. Require a clean worktree on `main`.
5. Compare the last tag and crates.io: `git tag -l`,
   `git ls-remote --tags origin`, and
   `https://crates.io/api/v1/crates/doppel` (also `doppel-cli`).
   `just tag-check` fails if any published version lacks a tag on `main`'s
   first-parent chain.
6. Run `just release-verify`: `check`, `audit`, `package`, `docs-check`,
   `changelog-check`, `tag-check`, then `release-test`. `release-test` runs the
   whole workspace with `PROPTEST_CASES=10000` (about six minutes) and fails if any
   test is skipped or ignored. Never lower the case count or filter tests to get
   green. A missing tool (for example `cargo-audit`) blocks the release; it is not a
   pass. Advisory findings block unless the owner accepts a documented exception.
7. Dry run from `main`: `cargo release <patch|minor> --workspace`. Review the
   version bump in both crates and the `doppel-cli` dependency pin, CHANGELOG
   stamping, the tag name and the push targets. The dry run fails off `main`.
8. After explicit owner approval: `cargo release <level> --workspace --execute`.
   Needs a crates.io token and push access to both remotes.
9. Verify with `scripts/check-tags.sh --after-release <version>`: the tag exists
   on `main`'s first-parent chain and on every push destination, both crates are
   on crates.io, and each `Cargo.toml` at the tag matches. Check the CHANGELOG
   compare links resolve.
10. Add a Completed line to `MASTER_PROGRESS.md`.

If `cargo release` fails after publishing `doppel` but before `doppel-cli`,
do not retry blindly: check crates.io state, then publish the remaining crate
by hand from the tagged commit. A version published without its tag is a policy
violation: create the tag on the exact commit that was published, from `main`'s
history, and push it; never move an existing tag.
