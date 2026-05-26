# step-01: Cargo workspace split — lib crate + cli subcrate

## Context

**Overall Objective:** Split single crate into workspace. Root = pure library. New `cli/` = binary + clap.

**Phase Context:** Wave 1. This is the structural foundation — no API changes, no behavioral changes.

**This Step:** Create the `cli/` subcrate, move `src/main.rs` and binary-exercising tests there,
update root `Cargo.toml` to be workspace + library-only, update documentation.

## Prerequisites

- All 79 tests pass: `cargo nextest run` reports 79 passed.
- Working directory is clean (`git status` shows nothing unexpected).

## Files to Read Before Starting

| File | Why |
|------|-----|
| `Cargo.toml` | Current deps, `[[bin]]`, `[features]` — must know what to remove |
| `src/main.rs` | Content moves to `cli/src/main.rs` unchanged — verify `use its_classified::` imports |
| `tests/spec/inv.rs` | Identify the 3 CARGO_BIN_EXE tests to extract (lines 410–511) |
| `tests/e2e.rs` | Moves to `cli/tests/e2e.rs` unchanged |
| `tests/e2e/cli.rs` | Moves to `cli/tests/e2e/cli.rs` unchanged |
| `TESTING.md` | Run commands section must be updated |

## Implementation

### Task 1: Create `cli/` directory structure

```sh
mkdir -p cli/src cli/tests/e2e cli/tests/cli_spec
```

### Task 2: Create `cli/Cargo.toml`

Write `cli/Cargo.toml` with this exact content:

```toml
[package]
name = "its-classified-cli"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "its-classified"
path = "src/main.rs"

[dependencies]
its-classified = { path = ".." }
clap = { version = "4", features = ["derive"] }

[dev-dependencies]
tempfile = "3"

[features]
test-e2e = []
```

### Task 3: Move `src/main.rs` → `cli/src/main.rs`

```sh
git mv src/main.rs cli/src/main.rs
```

Content is unchanged. It already uses `use its_classified::...` which resolves to the library
crate by name — works identically from a workspace member.

### Task 4: Move e2e tests to `cli/tests/`

```sh
git mv tests/e2e.rs cli/tests/e2e.rs
git mv tests/e2e/ cli/tests/e2e/
```

Content is unchanged. The `#![cfg(feature = "test-e2e")]` gate and `#[path = "e2e/cli.rs"] mod cli;`
work identically from `cli/tests/`.

### Task 5: Extract CLI spec tests to `cli/tests/cli_spec/`

Create `cli/tests/cli_spec.rs` with this exact content:

```rust
// CLI spec invariant tests — SPEC.md §Behavioral Invariants
// These tests exercise CLI binary behavior via CARGO_BIN_EXE.
// See also: tests/spec/ in the root library crate for non-CLI invariants.

#[path = "cli_spec/inv_cli.rs"]
mod inv_cli;
```

Create `cli/tests/cli_spec/inv_cli.rs` containing the 3 extracted test functions.
Copy lines 410–511 from `tests/spec/inv.rs` — the functions:
- `test_inv20_cli_no_key_flag_on_unscrub`
- `test_inv21_cli_scrub_key_file_mode_0600`
- `test_inv21_key_file_refuses_pre_existing_path`

The exact content of `cli/tests/cli_spec/inv_cli.rs`:

```rust
#[test]
fn test_inv20_cli_no_key_flag_on_unscrub() {
    // INV-20: "The CLI unscrub command MUST accept the session key only via
    //          ITS_CLASSIFIED_KEY environment variable; no other mechanism."
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_its-classified"))
        .args(["unscrub", "--help"])
        .output()
        .expect("failed to run its-classified");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        !help.contains("--key "),
        "INV-20: --key flag must not exist on unscrub subcommand"
    );
    assert!(
        !help.to_lowercase().contains("--key-"),
        "INV-20: no --key-* flags allowed"
    );
}

#[test]
fn test_inv21_cli_scrub_key_file_mode_0600() {
    // INV-21: "The CLI scrub command MUST create the session key output file
    //          with permission mode 0600."
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let entries_path = dir.path().join("entries.json");
        let key_path = dir.path().join("key.txt");
        let payload = b"no secrets here";
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_its-classified"))
            .args([
                "scrub",
                "--entries",
                entries_path.to_str().unwrap(),
                "--key-out",
                key_path.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.as_mut().unwrap().write_all(payload)?;
                c.wait()
            })
            .expect("failed to run scrub");
        assert!(status.success(), "scrub must exit 0");
        let meta = std::fs::metadata(&key_path).expect("key file must exist");
        let mode = meta.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "INV-21: key file mode must be 0600, got {:o}",
            mode
        );
    }
}

#[test]
fn test_inv21_key_file_refuses_pre_existing_path() {
    // INV-21: create_new (O_EXCL) MUST cause scrub to fail rather than write the
    // session key into a pre-existing inode whose permissions the attacker controls.
    #[cfg(unix)]
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let entries_path = dir.path().join("entries.json");
        let key_path = dir.path().join("key.txt");

        // Attacker pre-creates the file with world-readable permissions.
        std::fs::write(&key_path, b"").expect("pre-create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
        }

        let status = std::process::Command::new(env!("CARGO_BIN_EXE_its-classified"))
            .args([
                "scrub",
                "--entries",
                entries_path.to_str().unwrap(),
                "--key-out",
                key_path.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.as_mut().unwrap().write_all(b"no secrets")?;
                c.wait()
            })
            .expect("failed to run scrub");

        assert!(
            !status.success(),
            "INV-21: scrub MUST fail when --key-out path already exists (O_EXCL prevents mode race)"
        );
    }
}
```

### Task 6: Delete the 3 CLI tests from `tests/spec/inv.rs`

Remove lines 409–511 from `tests/spec/inv.rs` (the blank line before `test_inv20_cli_no_key_flag_on_unscrub`
through the closing brace of `test_inv21_key_file_refuses_pre_existing_path`).

The remaining tests in `tests/spec/inv.rs` do not use `CARGO_BIN_EXE` and continue to compile
against the library crate.

### Task 7: Update root `Cargo.toml`

Apply these changes to the root `Cargo.toml`:

1. **Add `[workspace]` section** at the very top of the file (before `[package]`):
   ```toml
   [workspace]
   members = [".", "cli"]
   ```

2. **Remove the `[[bin]]` section** (lines 12–14):
   ```toml
   [[bin]]
   name = "its-classified"
   path = "src/main.rs"
   ```

3. **Remove `clap` from `[dependencies]`** (line 27):
   ```toml
   clap = { version = "4", features = ["derive"] }
   ```

4. **Remove the `[features]` section entirely** (lines 35–36):
   ```toml
   [features]
   test-e2e = []
   ```

The resulting root `Cargo.toml` should be:

```toml
[workspace]
members = [".", "cli"]

[package]
name = "its-classified"
version = "0.1.0"
edition = "2024"

[profile.dev]
debug = 2

[profile.dev.package."*"]
debug = "line-tables-only"

[dependencies]
chacha20poly1305 = "0.10"
hmac = "0.12"
sha2 = "0.10"
rand = { version = "0.8", features = ["std", "std_rng"] }
zeroize = { version = "1", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
subtle = "2"
aho-corasick = "1"
log = "0.4"
thiserror = "1"

[dev-dependencies]
zeroize = { version = "1", features = ["derive"] }
rand = { version = "0.8", features = ["std", "std_rng"] }
tempfile = "3"
```

### Task 8: Update `TESTING.md` run commands

Replace the "Run Commands" section (lines 126–132) with:

```sh
cargo nextest run                                                            # all workspace tests
cargo nextest run -p its-classified --test spec                              # lib spec invariants
cargo nextest run -p its-classified-cli --test cli_spec                      # CLI spec invariants
cargo nextest run -p its-classified --test integration                       # integration only
cargo nextest run -p its-classified-cli --features test-e2e --test e2e       # e2e
cargo nextest run --lib                                                      # unit tests only
```

Also update the Test Tiers table (lines 45–49). Add a note that CLI-specific spec tests live
in the `cli` crate:

| Tier | Entry point | Subdirectory | What it covers |
|---|---|---|---|
| **Spec invariants (lib)** | `tests/spec.rs` | `tests/spec/` | Library SPEC.md MUST/MUST NOT invariants |
| **Spec invariants (CLI)** | `cli/tests/cli_spec.rs` | `cli/tests/cli_spec/` | CLI-specific SPEC.md invariants (INV-20, INV-21) |
| **Integration** | `tests/integration.rs` | `tests/integration/` | Public-API behavior: full scrub→unscrub cycles |
| **E2E** | `cli/tests/e2e.rs` | `cli/tests/e2e/` | CLI process boundary tests; gated by `--features test-e2e` |

### Task 9: Commit

```sh
git add -A
git commit -m "step-01: workspace split — lib crate + cli subcrate"
```

## Acceptance Criteria

1. `cargo nextest run` exits 0, reports exactly 79 tests passed (76 lib + 3 cli_spec).
2. `cargo build -p its-classified` exits 0 (lib compiles without clap).
3. `cargo tree -p its-classified | grep -i clap` produces no output (clap not in lib dependency tree).
4. `cargo build -p its-classified-cli` exits 0.
5. `ls -la target/debug/its-classified` shows the binary exists.
6. `cargo clippy --workspace` exits 0 with no warnings.
7. `cargo fmt --all --check` exits 0.
8. `tests/spec/inv.rs` does NOT contain the string `CARGO_BIN_EXE` (verify: `grep CARGO_BIN_EXE tests/spec/inv.rs` exits non-zero).
9. `cli/tests/cli_spec/inv_cli.rs` contains all 3 extracted test functions.
10. `tests/e2e.rs` does not exist at root (verify: `test ! -f tests/e2e.rs`).

## Reviewer Instructions

Run these commands in order. All must pass.

```sh
cargo nextest run 2>&1 | tail -3
# Expected: "79 tests run: 79 passed, 0 skipped"

cargo tree -p its-classified | grep -ic clap
# Expected: 0

cargo build -p its-classified-cli && file target/debug/its-classified
# Expected: ELF binary

grep -c CARGO_BIN_EXE tests/spec/inv.rs; echo "exit: $?"
# Expected: 0 matches, or grep exits non-zero

grep -c CARGO_BIN_EXE cli/tests/cli_spec/inv_cli.rs
# Expected: 3

cargo clippy --workspace 2>&1 | grep -c warning
# Expected: 0

cargo fmt --all --check
# Expected: exit 0
```

## Rollback

```sh
git reset --hard HEAD~1
cargo nextest run   # verify baseline restored
```
