# Releasing doppel

`doppel` and `doppel-cli` share one version and release together with
`cargo-release` (`release.toml`). Preparation is not authorization to publish:
`--execute` uploads to crates.io, tags and pushes, and cannot be undone.

## Conventions

- Version source of truth: `version` in `doppel/Cargo.toml` and
  `doppel-cli/Cargo.toml`, kept equal. `doppel-cli` also pins `doppel` by
  `version`; `cargo-release` bumps it.
- Tag: `v<version>` (for example `v0.1.0`), created by the `doppel` crate, on the
  release commit `chore: release v<version>`.
- Pre-1.0 semver: a minor bump (0.x.0) for breaking changes, a patch bump for
  fixes and additive changes.
- crates.io versions are immutable. Never move a published tag; to repair a bad
  release, yank the version and release a new one.
- Feature and preparation work lands on branches merged with `--no-ff`. Only
  the generated release commit is made directly on `main`.
- Origin fetches from SourceHut and pushes to both SourceHut and GitHub. Query
  both when checking tags.

## Checklist

1. Move finished plans to Completed in `MASTER_PROGRESS.md`; confirm README and
   docs describe any behavior change.
2. Write `CHANGELOG.md` entries under `[Unreleased]`: Added, Changed, Fixed,
   Documentation, Testing. Flag behavior changes explicitly.
3. Merge to `main` with `--no-ff`. Require a clean worktree on `main`.
4. Compare the last tag and crates.io: `git tag -l`,
   `git ls-remote --tags origin`, and
   `https://crates.io/api/v1/crates/doppel` (also `doppel-cli`).
5. Run `just verify`. Optionally scale properties:
   `PROPTEST_CASES=10000 just test-property`. A missing tool (for example
   `cargo-audit`) blocks the release; it is not a pass. Advisory findings block
   unless the owner accepts a documented exception.
6. Dry run from `main`: `cargo release <patch|minor> --workspace`. Review the
   version bump in both crates and the `doppel-cli` dependency pin, CHANGELOG
   stamping, the tag name and the push targets. The dry run fails off `main`.
7. After explicit owner approval: `cargo release <level> --workspace --execute`.
   Needs a crates.io token and push access to both remotes.
8. Verify: the tag exists on both remotes, both crates show the new version on
   crates.io, and the CHANGELOG compare links resolve.
9. Add a Completed line to `MASTER_PROGRESS.md`.

If `cargo release` fails after publishing `doppel` but before `doppel-cli`,
do not retry blindly: check crates.io state, then publish the remaining crate
by hand from the tagged commit.
