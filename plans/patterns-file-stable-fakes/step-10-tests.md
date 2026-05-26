# Step 10: New Tests and Test Updates

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 6 (final). All code changes are complete. This step adds new tests for the patterns file feature, updates existing e2e/CLI tests to pass `--patterns`, and adds cross-run stability tests for INV-13.

### This Step
Update all existing e2e and CLI spec tests to use `--patterns`. Add new e2e tests for `init`, `register`, and error cases. Add INV-13 cross-run stability tests at both library and CLI levels. Add patterns file serialization spec tests.

## Prerequisites
- Step 09 complete (CLI supports `init`, `register`, `--patterns`)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/cli/tests/e2e/cli.rs` — existing e2e tests, full file
- `/home/ignacio/pr/its-classified/cli/tests/cli_spec/inv_cli.rs` — existing CLI spec tests
- `/home/ignacio/pr/its-classified/tests/spec/inv.rs` — existing library spec tests
- `/home/ignacio/pr/its-classified/cli/tests/e2e.rs` — e2e test harness entry point
- `/home/ignacio/pr/its-classified/cli/tests/cli_spec.rs` — CLI spec entry point

## Implementation

### Task 1: Add shared test helper for patterns file creation

In `cli/tests/e2e/cli.rs`, add a helper function at the top (after the existing helpers):

```rust
fn create_test_patterns_file(name: &str) -> PathBuf {
    let path = tmp_path(&format!("{name}-patterns.json"));
    let output = Command::new(bin())
        .args(["init", "--patterns", path.to_str().unwrap(), "--force"])
        .output()
        .expect("failed to run init");
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}
```

### Task 2: Update existing e2e tests to use `--patterns`

**`test_e2e_key_file_mode_0600`** (line 25): Add patterns file creation and pass `--patterns` to scrub:

```rust
#[test]
fn test_e2e_key_file_mode_0600() {
    let patterns_path = create_test_patterns_file("key-mode");
    let entries_path = tmp_path("entries.json");
    let key_path = tmp_path("key.txt");

    let mut child = Command::new(bin())
        .args([
            "scrub",
            "--patterns",
            patterns_path.to_str().unwrap(),
            "--entries",
            entries_path.to_str().unwrap(),
            "--key-out",
            key_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start scrub");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"test payload with no secrets")
        .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "scrub failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&key_path).expect("key file must exist");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "INV-21: key file must have mode 0600, got {:03o}",
            mode
        );
    }

    cleanup(&[&patterns_path, &entries_path, &key_path]);
}
```

**`test_e2e_unscrub_streams_before_eof`** (line 92): Add patterns file, pass `--patterns` to scrub:

Update the scrub child command to include `"--patterns", patterns_path.to_str().unwrap()` in the args array. Add `let patterns_path = create_test_patterns_file("stream");` before the scrub child. Add `&patterns_path` to the cleanup call.

**`test_e2e_full_round_trip`** (line 168): Same pattern — add patterns file, pass `--patterns`:

Add `let patterns_path = create_test_patterns_file("round-trip");` at the start. Insert `"--patterns", patterns_path.to_str().unwrap(),` into the scrub args. Add to cleanup.

### Task 3: Update CLI spec tests

In `cli/tests/cli_spec/inv_cli.rs`, check each test:

- **`test_inv21_cli_scrub_key_file_mode_0600`**: Same update as e2e — add patterns file, pass `--patterns`.
- **`test_inv21_key_file_refuses_pre_existing_path`**: Same update.

Use the same `create_test_patterns_file` helper pattern. If `cli/tests/cli_spec/inv_cli.rs` doesn't have the helper, add one there too (or create a shared module).

### Task 4: Add new e2e tests

Add the following tests to `cli/tests/e2e/cli.rs`:

```rust
#[test]
fn test_e2e_init_creates_patterns_file() {
    let path = tmp_path("init-test-patterns.json");
    let _ = std::fs::remove_file(&path);

    let output = Command::new(bin())
        .args(["init", "--patterns", path.to_str().unwrap()])
        .output()
        .expect("failed to run init");

    assert!(output.status.success(), "init must succeed");
    assert!(path.exists(), "patterns file must be created");

    let data = std::fs::read(&path).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&data).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["tier1"].as_object().unwrap().len(), 8);
    assert!(json["tier2"].as_array().unwrap().is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "patterns file must have mode 0600");
    }

    cleanup(&[&path]);
}

#[test]
fn test_e2e_init_refuses_existing_file() {
    let path = tmp_path("init-existing-patterns.json");
    std::fs::write(&path, b"existing").unwrap();

    let output = Command::new(bin())
        .args(["init", "--patterns", path.to_str().unwrap()])
        .output()
        .expect("failed to run init");

    assert!(!output.status.success(), "init must fail when file exists");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists"),
        "error must mention file exists"
    );

    cleanup(&[&path]);
}

#[test]
fn test_e2e_init_force_overwrites() {
    let path = tmp_path("init-force-patterns.json");
    std::fs::write(&path, b"garbage").unwrap();

    let output = Command::new(bin())
        .args([
            "init",
            "--patterns",
            path.to_str().unwrap(),
            "--force",
        ])
        .output()
        .expect("failed to run init");

    assert!(output.status.success(), "init --force must succeed");
    let data = std::fs::read(&path).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&data).unwrap();
    assert_eq!(json["version"], 1);

    cleanup(&[&path]);
}

#[test]
fn test_e2e_scrub_missing_patterns_file() {
    let entries_path = tmp_path("entries-missing-pat.json");
    let key_path = tmp_path("key-missing-pat.txt");

    let output = Command::new(bin())
        .args([
            "scrub",
            "--patterns",
            "/tmp/nonexistent-patterns-file.json",
            "--entries",
            entries_path.to_str().unwrap(),
            "--key-out",
            key_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run scrub");

    assert!(!output.status.success(), "scrub must fail with missing patterns file");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("No such file"),
        "error must mention file not found: {stderr}"
    );

    cleanup(&[&entries_path, &key_path]);
}

#[test]
fn test_e2e_scrub_corrupt_patterns_file() {
    let patterns_path = tmp_path("corrupt-patterns.json");
    std::fs::write(&patterns_path, b"not valid json").unwrap();
    let entries_path = tmp_path("entries-corrupt.json");
    let key_path = tmp_path("key-corrupt.txt");

    let output = Command::new(bin())
        .args([
            "scrub",
            "--patterns",
            patterns_path.to_str().unwrap(),
            "--entries",
            entries_path.to_str().unwrap(),
            "--key-out",
            key_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run scrub");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "error must indicate invalid patterns: {stderr}"
    );

    cleanup(&[&patterns_path, &entries_path, &key_path]);
}

#[test]
fn test_e2e_register_tier2_round_trip() {
    let patterns_path = create_test_patterns_file("register-rt");
    let entries_path = tmp_path("entries-register-rt.json");
    let key_path = tmp_path("key-register-rt.txt");
    let secret = b"my-custom-api-token-that-is-long-enough-for-test";

    // Register secret
    let mut register_child = Command::new(bin())
        .args(["register", "--patterns", patterns_path.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start register");
    register_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(secret)
        .unwrap();
    drop(register_child.stdin.take());
    let register_out = register_child.wait_with_output().unwrap();
    assert!(
        register_out.status.success(),
        "register failed: {}",
        String::from_utf8_lossy(&register_out.stderr)
    );

    // Scrub payload containing the secret
    let payload = [b"token: ".as_slice(), secret, b" end"].concat();
    let mut scrub_child = Command::new(bin())
        .args([
            "scrub",
            "--patterns",
            patterns_path.to_str().unwrap(),
            "--entries",
            entries_path.to_str().unwrap(),
            "--key-out",
            key_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start scrub");
    scrub_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&payload)
        .unwrap();
    drop(scrub_child.stdin.take());
    let scrub_out = scrub_child.wait_with_output().unwrap();
    assert!(
        scrub_out.status.success(),
        "scrub failed: {}",
        String::from_utf8_lossy(&scrub_out.stderr)
    );

    let scrubbed = &scrub_out.stdout;
    assert!(
        !scrubbed.windows(secret.len()).any(|w| w == secret),
        "scrubbed output must not contain original secret"
    );

    // Unscrub
    let key_hex = std::fs::read_to_string(&key_path)
        .unwrap()
        .trim()
        .to_string();
    let mut unscrub_child = Command::new(bin())
        .args(["unscrub", "--entries", entries_path.to_str().unwrap()])
        .env("ITS_CLASSIFIED_KEY", &key_hex)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start unscrub");
    unscrub_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(scrubbed)
        .unwrap();
    drop(unscrub_child.stdin.take());
    let unscrub_out = unscrub_child.wait_with_output().unwrap();
    assert!(
        unscrub_out.status.success(),
        "unscrub failed: {}",
        String::from_utf8_lossy(&unscrub_out.stderr)
    );
    assert_eq!(
        unscrub_out.stdout, payload,
        "round-trip: restored output must match original"
    );

    cleanup(&[&patterns_path, &entries_path, &key_path]);
}

#[test]
fn test_e2e_register_missing_patterns_file() {
    let output = Command::new(bin())
        .args(["register", "--patterns", "/tmp/nonexistent-register.json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.as_mut().unwrap().write_all(b"secret")?;
            drop(child.stdin.take());
            child.wait_with_output()
        })
        .expect("failed to run register");

    assert!(!output.status.success());
}

#[test]
fn test_e2e_register_empty_stdin() {
    let patterns_path = create_test_patterns_file("register-empty");

    let output = Command::new(bin())
        .args(["register", "--patterns", patterns_path.to_str().unwrap()])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("failed to run register");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no secret") || stderr.contains("empty"),
        "error must mention empty stdin: {stderr}"
    );

    cleanup(&[&patterns_path]);
}
```

### Task 5: Add INV-13 cross-run stability test (e2e)

```rust
#[test]
fn test_e2e_inv13_cross_run_fake_stability() {
    // INV-13: Two separate scrub invocations with the same patterns file
    // and same secret must produce the same fake.
    let patterns_path = create_test_patterns_file("inv13-cross");
    let entries1_path = tmp_path("entries-inv13-1.json");
    let key1_path = tmp_path("key-inv13-1.txt");
    let entries2_path = tmp_path("entries-inv13-2.json");
    let key2_path = tmp_path("key-inv13-2.txt");

    let payload = b"key: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";

    for (ep, kp) in [(&entries1_path, &key1_path), (&entries2_path, &key2_path)] {
        let mut child = Command::new(bin())
            .args([
                "scrub",
                "--patterns", patterns_path.to_str().unwrap(),
                "--entries", ep.to_str().unwrap(),
                "--key-out", kp.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(payload).unwrap();
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "scrub failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    // Both scrubbed outputs must be identical (same patterns file = same salts = same fakes)
    // We can't easily compare stdout across runs since we consumed it, so compare entries:
    let e1_data = std::fs::read(&entries1_path).unwrap();
    let e2_data = std::fs::read(&entries2_path).unwrap();
    let e1: serde_json::Value = serde_json::from_slice(&e1_data).unwrap();
    let e2: serde_json::Value = serde_json::from_slice(&e2_data).unwrap();

    assert_eq!(
        e1[0]["fake"], e2[0]["fake"],
        "INV-13: same secret + same patterns file must produce same fake across runs"
    );

    cleanup(&[&patterns_path, &entries1_path, &key1_path, &entries2_path, &key2_path]);
}
```

### Task 6: Add INV-13 cross-serialization test (library level)

In `tests/spec/inv.rs`, add:

```rust
#[test]
fn test_inv13_cross_serialization_fake_stability() {
    // INV-13: register → serialize patterns → deserialize → scrub → same fake
    use its_classified::{PatternsFile, register_with_options, RegistrationOptions, scrub};

    its_classified::tier1::init_test_salts();

    let secret = b"my-custom-secret-for-cross-serial-test";
    let pat = register_with_options(secret, &RegistrationOptions::default()).unwrap();

    let mut pf = PatternsFile::new();
    pf.generate_missing_tier1_salts();
    pf.add_tier2_pattern(&pat).unwrap();

    // Scrub with original pattern
    let payload = [b"token: ".as_slice(), secret].concat();
    let result1 = scrub(&payload, &[pat]).unwrap();

    // Serialize + deserialize patterns file
    let bytes = pf.serialize().unwrap();
    let pf2 = PatternsFile::deserialize(&bytes).unwrap();
    let patterns2 = pf2.into_patterns().unwrap();

    // Scrub with reconstructed patterns
    let result2 = scrub(&payload, &patterns2).unwrap();

    assert_eq!(
        result1.entries[0].fake, result2.entries[0].fake,
        "INV-13: same secret through serialized patterns must produce same fake"
    );
}
```

### Task 7: Add serde_json dev-dependency to CLI if needed

In `cli/Cargo.toml`, check if `serde_json` is in `[dev-dependencies]`. The e2e tests above use `serde_json::Value`. If not present, add:

```toml
[dev-dependencies]
tempfile = "3"
serde_json = "1"
```

### Task 8: Run all tests

```sh
cargo nextest run --workspace
cargo nextest run -p its-classified-cli --features test-e2e --test e2e
```

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo nextest run -p its-classified --test spec 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified --test integration 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified --lib 2>&1 | tail -3` shows 0 failures
- [ ] `cargo nextest run -p its-classified-cli --features test-e2e --test e2e 2>&1 | tail -5` shows 0 failures
- [ ] `grep -c "test_e2e_init_creates_patterns_file" /home/ignacio/pr/its-classified/cli/tests/e2e/cli.rs` outputs `1`
- [ ] `grep -c "test_e2e_register_tier2_round_trip" /home/ignacio/pr/its-classified/cli/tests/e2e/cli.rs` outputs `1`
- [ ] `grep -c "test_e2e_inv13_cross_run_fake_stability" /home/ignacio/pr/its-classified/cli/tests/e2e/cli.rs` outputs `1`
- [ ] `grep -c "test_inv13_cross_serialization_fake_stability" /home/ignacio/pr/its-classified/tests/spec/inv.rs` outputs `1`
- [ ] `grep -c "create_test_patterns_file" /home/ignacio/pr/its-classified/cli/tests/e2e/cli.rs` outputs at least `5`

## Reviewer Instructions

You are reviewing Step 10. Verify:
1. Run `cargo nextest run --workspace` — all lib/spec/integration tests pass
2. Run `cargo nextest run -p its-classified-cli --features test-e2e --test e2e` — all e2e tests pass
3. Check that ALL existing e2e tests now pass `--patterns` to scrub
4. Check that `test_e2e_init_creates_patterns_file` verifies file creation, JSON structure, permissions
5. Check that `test_e2e_register_tier2_round_trip` does full register→scrub→unscrub cycle
6. Check that `test_e2e_inv13_cross_run_fake_stability` runs two separate scrub invocations and compares fakes
7. Check that `test_inv13_cross_serialization_fake_stability` verifies fake stability across serialize/deserialize
8. Run `cargo clippy --workspace 2>&1` — no new warnings
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- cli/tests/ tests/ cli/Cargo.toml
```
