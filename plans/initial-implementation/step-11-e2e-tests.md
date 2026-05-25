# Step 11: E2E Tests and Nextest Config

## Context

### Overall Objective
Build `its-classified`: secret scrubbing and streaming restoration.

### Phase Context
Wave 7 (final step, sequential after Wave 6). Adds CLI-level E2E tests verifying
the process boundary behavior: key file mode (INV-21), env var key delivery (INV-20),
and streaming output-before-EOF (SPEC §CLI Contract / VC-9). Adds nextest configuration.

### This Step
Implement `tests/e2e/cli.rs`, update `tests/e2e.rs` to include the module, and create
`.config/nextest.toml`. E2E tests are gated by `--features test-e2e` and invoke the
built binary via `std::process::Command`.

## Prerequisites

- Step 08 complete (CLI binary built and functional)
- Step 09 complete (spec tests pass)
- Step 10 complete (integration tests pass)

## Files to Read Before Starting

- `tests/e2e.rs` — current stub (`#![cfg(feature = "test-e2e")]`)
- `tests/e2e/` — empty directory
- `SPEC.md §CLI Contract`, `INV-20, INV-21`
- `TESTING.md §CLI` test vectors

## Implementation

### Task 1: .config/nextest.toml

Create `.config/nextest.toml` at repo root:

```toml
[profile.default]
test-threads = "num-cpus"

[profile.ci]
test-threads = 1
fail-fast = true
```

### Task 2: tests/e2e.rs — add module

```rust
// E2E tests — CLI process boundary.
// Gated by: cargo nextest run --features test-e2e --test e2e
#![cfg(feature = "test-e2e")]

mod cli;
```

### Task 3: tests/e2e/cli.rs

```rust
use std::process::Command;
use std::io::Write;
use std::path::PathBuf;

// Path to the built binary
fn bin() -> PathBuf {
    // Use the binary built by cargo test
    let mut path = std::env::current_exe().unwrap();
    path.pop();  // remove the test binary name
    // Navigate to deps or the binary location
    // In nextest: CARGO_BIN_EXE_its-classified is set
    PathBuf::from(env!("CARGO_BIN_EXE_its-classified"))
}

fn tmp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("its-classified-e2e-{}-{}", name, std::process::id()))
}

fn cleanup(paths: &[&PathBuf]) {
    for p in paths { let _ = std::fs::remove_file(p); }
}

// VC-8 / INV-21: scrub creates session key file with mode 0600
#[test]
fn test_e2e_key_file_mode_0600() {
    let entries_path = tmp_path("entries.json");
    let key_path = tmp_path("key.txt");

    let scrub_output = Command::new(bin())
        .args(["scrub", "--entries", entries_path.to_str().unwrap(),
               "--key-out", key_path.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start scrub");

    // Write test payload to stdin
    let mut child = scrub_output;
    child.stdin.as_mut().unwrap().write_all(b"test payload with no secrets").unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "scrub failed: {:?}", String::from_utf8_lossy(&output.stderr));

    // Verify key file mode on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&key_path).expect("key file must exist");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "INV-21: key file must have mode 0600, got {:o}", mode);
    }

    cleanup(&[&entries_path, &key_path]);
}

// INV-20: unscrub reads key from ITS_CLASSIFIED_KEY only (no --key flag accepted)
#[test]
fn test_e2e_unscrub_no_key_flag() {
    let help_output = Command::new(bin())
        .args(["unscrub", "--help"])
        .output()
        .expect("failed to get help");
    let help_text = String::from_utf8_lossy(&help_output.stdout);
    assert!(!help_text.contains("--key "),
            "INV-20: --key flag must not appear in unscrub --help");
    assert!(!help_text.to_lowercase().contains("--key-file"),
            "INV-20: --key-file must not appear in unscrub --help");
}

// VC-9: unscrub writes to stdout before stdin reaches EOF (streaming)
#[test]
fn test_e2e_unscrub_streams_before_eof() {
    use std::io::Read;
    use std::thread;

    // First, scrub a payload to get entries and key
    let entries_path = tmp_path("entries-stream.json");
    let key_path = tmp_path("key-stream.txt");
    let payload = b"Hello, world! No secrets here.";

    let mut scrub_child = Command::new(bin())
        .args(["scrub", "--entries", entries_path.to_str().unwrap(),
               "--key-out", key_path.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    scrub_child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    drop(scrub_child.stdin.take());
    let scrub_out = scrub_child.wait_with_output().unwrap();
    assert!(scrub_out.status.success());

    let scrubbed = scrub_out.stdout;
    let key_hex = std::fs::read_to_string(&key_path).unwrap().trim().to_string();

    // Now run unscrub with a slow stdin: write first half, wait, write second half
    let mut unscrub_child = Command::new(bin())
        .args(["unscrub", "--entries", entries_path.to_str().unwrap()])
        .env("ITS_CLASSIFIED_KEY", &key_hex)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let mut stdin = unscrub_child.stdin.take().unwrap();
    let mut stdout = unscrub_child.stdout.take().unwrap();

    let half = scrubbed.len() / 2;
    let first_half = scrubbed[..half].to_vec();
    let second_half = scrubbed[half..].to_vec();

    // Write first half in a thread, then check stdout for output before writing second half
    let writer = thread::spawn(move || {
        stdin.write_all(&first_half).unwrap();
        // Short sleep to give unscrub time to process first half
        thread::sleep(std::time::Duration::from_millis(50));
        stdin.write_all(&second_half).unwrap();
        // stdin drops here, closing the pipe
    });

    // Read all stdout (process will exit once stdin is closed)
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    writer.join().unwrap();

    let status = unscrub_child.wait().unwrap();
    assert!(status.success(), "unscrub failed");
    assert_eq!(output, payload, "VC-9: round-trip output must match original");

    cleanup(&[&entries_path, &key_path]);
}

// Full E2E round-trip: scrub + unscrub at process boundary
#[test]
fn test_e2e_full_round_trip() {
    use std::io::Read;

    let entries_path = tmp_path("entries-rt.json");
    let key_path = tmp_path("key-rt.txt");

    // Synthetic Anthropic key for testing
    let payload = b"Authorization: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA end";

    // Step 1: scrub
    let mut scrub_child = Command::new(bin())
        .args(["scrub", "--entries", entries_path.to_str().unwrap(),
               "--key-out", key_path.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    scrub_child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    drop(scrub_child.stdin.take());
    let scrub_out = scrub_child.wait_with_output().unwrap();
    assert!(scrub_out.status.success(),
            "scrub failed: {}", String::from_utf8_lossy(&scrub_out.stderr));
    let scrubbed = scrub_out.stdout;
    let key_hex = std::fs::read_to_string(&key_path).unwrap().trim().to_string();

    // Verify scrubbed output doesn't contain original key
    assert!(!scrubbed.windows(b"sk-ant-api03-AAAA".len())
        .any(|w| w.starts_with(b"sk-ant-api03-AAAA")),
        "scrubbed output must not contain original key pattern");

    // Step 2: unscrub
    let mut unscrub_child = Command::new(bin())
        .args(["unscrub", "--entries", entries_path.to_str().unwrap()])
        .env("ITS_CLASSIFIED_KEY", &key_hex)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    unscrub_child.stdin.as_mut().unwrap().write_all(&scrubbed).unwrap();
    drop(unscrub_child.stdin.take());
    let unscrub_out = unscrub_child.wait_with_output().unwrap();
    assert!(unscrub_out.status.success(),
            "unscrub failed: {}", String::from_utf8_lossy(&unscrub_out.stderr));
    assert_eq!(unscrub_out.stdout, payload, "E2E round-trip: restored output must match original");

    cleanup(&[&entries_path, &key_path]);
}

// INV-20: missing ITS_CLASSIFIED_KEY → non-zero exit
#[test]
fn test_e2e_unscrub_missing_env_var_fails() {
    let entries_path = tmp_path("entries-missing.json");
    // Write a minimal valid entries file (empty array)
    std::fs::write(&entries_path, b"[]").unwrap();
    let output = Command::new(bin())
        .args(["unscrub", "--entries", entries_path.to_str().unwrap()])
        // Do NOT set ITS_CLASSIFIED_KEY
        .env_remove("ITS_CLASSIFIED_KEY")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success(),
            "INV-20: missing ITS_CLASSIFIED_KEY must cause non-zero exit");
    cleanup(&[&entries_path]);
}
```

## Acceptance Criteria

- [ ] `cargo nextest run --features test-e2e --test e2e` exits 0 (on Linux)
- [ ] `test_e2e_key_file_mode_0600` passes (INV-21: `stat -c %a` shows 600)
- [ ] `test_e2e_unscrub_no_key_flag` passes (INV-20: --key absent from help)
- [ ] `test_e2e_full_round_trip` passes (end-to-end correctness)
- [ ] `test_e2e_unscrub_missing_env_var_fails` passes (INV-20: missing env var → error)
- [ ] `.config/nextest.toml` exists with `[profile.default]` and `[profile.ci]` sections
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions

You are reviewing Step 11. Verify:

1. Run `cargo nextest run --features test-e2e --test e2e` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Confirm `.config/nextest.toml` exists: `cat .config/nextest.toml`
4. Confirm key file mode test uses `PermissionsExt::mode()` and checks `0o600` exactly
5. Run `cargo nextest run` (without e2e feature) — must still exit 0 (e2e tests must be gated)

Report: "PASS" or "FAIL: <criterion> — <detail>"

## Rollback

`git revert` step-11 commit. This is the final step; rollback restores step-09+10 state.
