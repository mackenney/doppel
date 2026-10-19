# Releasing doppel

`doppel` and `doppel-cli` share one version and release together with
`cargo-release` (`release.toml`). Checklist steps 1-7 (changelog, docs,
verification, dry run) are preparation; none of them publishes. `--execute`
(step 8) uploads to crates.io, tags and pushes, and cannot be undone.

## The release commit

`cargo release --execute` is the only thing that commits directly to `main`.
It runs on a clean, up-to-date `main` and makes exactly one commit,
`chore: release v<version>`, which:

- has a single parent (the previous `main` tip) and is not a merge, so it
  cannot create a foxtrot merge and keeps `main`'s first-parent chain linear;
- contains the whole mechanical change: version bump in both crates, the
  `doppel-cli` pin of `doppel`, and the CHANGELOG stamp (`[Unreleased]` becomes
  the version and date, a fresh `[Unreleased]` is re-inserted, compare links
  updated);
- is the commit that gets published and tagged `v<version>`.

Humans and agents never make these edits by hand or on a feature branch: the
CHANGELOG `[Unreleased]` content is hand-written and merged `--no-ff` like any
other work, and `cargo-release` does the rest. After `--execute` pushes `main`,
do not amend, rebase or merge on top of the release commit before it is pushed
to both remotes. The tag therefore points at this release commit, never at a
feature merge.

## Conventions

- Version source of truth: `version` in `doppel/Cargo.toml` and
  `doppel-cli/Cargo.toml`, kept equal. `doppel-cli` also pins `doppel` by
  `version`; `cargo-release` bumps it.
- Tag: `v<version>` (for example `v0.1.0`), created by the `doppel` crate, on the
  release commit `chore: release v<version>` (see above). Tags are mandatory:
  every version published to crates.io MUST have its tag, and the tagged commit
  MUST be on `main`'s first-parent chain, never a feature-branch commit. The
  release commit satisfies this by construction. `0.0.1` predates this rule and
  is the only exception (`scripts/check-tags.sh`).
- Pre-1.0 semver: a minor bump (0.x.0) for breaking changes, a patch bump for
  fixes and additive changes.
- crates.io versions are immutable. Never move a published tag; to repair a bad
  release, yank the version and release a new one.
- Feature and preparation work (including CHANGELOG and docs edits) lands on
  branches merged with `--no-ff`. Only the generated release commit is made
  directly on `main`.
- Origin fetches from SourceHut and pushes to both SourceHut and GitHub. Query
  both when checking tags.

## Checklist

1. Update `MASTER_PROGRESS.md`: remove finished plans and fixed gaps. History
   belongs in the CHANGELOG (step 2), not there.
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
8. After explicit owner approval, with `main` clean and unchanged since step 6
   (otherwise re-run `just release-verify`):
   `cargo release <level> --workspace --execute`. This creates the single
   release commit on `main`, publishes both crates, tags `v<version>` and pushes
   `main` and the tag to both remotes. Needs a crates.io token and push access
   to both remotes.
9. Verify with `scripts/check-tags.sh --after-release <version>`: the tag exists
   on `main`'s first-parent chain, is the single-parent
   `chore: release v<version>` commit, and is on every push destination, both crates are
   on crates.io, and each `Cargo.toml` at the tag matches. Check the CHANGELOG
   compare links resolve.

If `cargo release` fails after publishing `doppel` but before `doppel-cli`,
do not retry blindly: check crates.io state, then publish the remaining crate
by hand from the tagged commit. A version published without its tag is a policy
violation: create the tag on the exact commit that was published, from `main`'s
history, and push it; never move an existing tag.
