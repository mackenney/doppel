# Progress

## Status
In Progress

## Tasks

- [x] step-03: flatten ScrubError — no internal type leakage (commit 8486afd)

## Files Changed

- src/types.rs — ScrubError: added #[non_exhaustive], replaced #[from] tuple variants with {msg: String} struct variants, added manual From impls
- src/fake.rs — FakeError: pub → pub(crate)
- src/crypto.rs — Error: pub → pub(crate)

## Notes

79/79 tests pass. clippy clean. fmt clean.
