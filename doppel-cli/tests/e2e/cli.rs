use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_doppel"))
}

fn tmp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("doppel-e2e-{}-{}", name, std::process::id()))
}

fn cleanup(paths: &[&PathBuf]) {
    for p in paths {
        let _ = std::fs::remove_file(p);
    }
}

fn create_test_patterns_file(name: &str) -> PathBuf {
    let path = tmp_path(&format!("{name}-secrets.toml"));
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

// VC-8 / INV-21: swap creates session key file with mode 0600
#[test]
fn test_e2e_key_file_mode_0600() {
    let patterns_path = create_test_patterns_file("key-mode");
    let entries_path = tmp_path("entries.json");
    let key_path = tmp_path("key.txt");

    let mut child = Command::new(bin())
        .args([
            "swap",
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
        .expect("failed to start swap");

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
        "swap failed: {:?}",
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

// INV-20: restore reads key from DOPPEL_KEY only (no --key flag accepted)
#[test]
fn test_e2e_restore_no_key_flag() {
    let help_output = Command::new(bin())
        .args(["restore", "--help"])
        .output()
        .expect("failed to get help");
    let help_text = String::from_utf8_lossy(&help_output.stdout);
    assert!(
        !help_text.contains("--key "),
        "INV-20: --key flag must not appear in restore --help"
    );
    assert!(
        !help_text.to_lowercase().contains("--key-file"),
        "INV-20: --key-file must not appear in restore --help"
    );
}

// VC-9: restore writes to stdout before stdin reaches EOF (streaming)
#[test]
fn test_e2e_restore_streams_before_eof() {
    use std::io::Read;
    use std::thread;

    let patterns_path = create_test_patterns_file("stream");
    let entries_path = tmp_path("entries-stream.json");
    let key_path = tmp_path("key-stream.txt");
    let payload = b"Hello, world! No secrets here.";

    let mut scrub_child = Command::new(bin())
        .args([
            "swap",
            "--patterns",
            patterns_path.to_str().unwrap(),
            "--entries",
            entries_path.to_str().unwrap(),
            "--key-out",
            key_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    scrub_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload)
        .unwrap();
    drop(scrub_child.stdin.take());
    let scrub_out = scrub_child.wait_with_output().unwrap();
    assert!(scrub_out.status.success());

    let scrubbed = scrub_out.stdout;
    let key_hex = std::fs::read_to_string(&key_path)
        .unwrap()
        .trim()
        .to_string();

    let mut unscrub_child = Command::new(bin())
        .args(["restore", "--entries", entries_path.to_str().unwrap()])
        .env("DOPPEL_KEY", &key_hex)
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

    let writer = thread::spawn(move || {
        stdin.write_all(&first_half).unwrap();
        thread::sleep(std::time::Duration::from_millis(50));
        stdin.write_all(&second_half).unwrap();
    });

    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    writer.join().unwrap();

    let status = unscrub_child.wait().unwrap();
    assert!(status.success(), "restore failed");
    assert_eq!(
        output, payload,
        "VC-9: round-trip output must match original"
    );

    cleanup(&[&patterns_path, &entries_path, &key_path]);
}

// Full E2E round-trip: swap + restore at process boundary
#[test]
fn test_e2e_full_round_trip() {
    let patterns_path = create_test_patterns_file("round-trip");
    let entries_path = tmp_path("entries-rt.json");
    let key_path = tmp_path("key-rt.txt");

    let payload = b"Authorization: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA end";

    let mut scrub_child = Command::new(bin())
        .args([
            "swap",
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
        .unwrap();
    scrub_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload)
        .unwrap();
    drop(scrub_child.stdin.take());
    let scrub_out = scrub_child.wait_with_output().unwrap();
    assert!(
        scrub_out.status.success(),
        "swap failed: {}",
        String::from_utf8_lossy(&scrub_out.stderr)
    );
    let scrubbed = scrub_out.stdout;
    let key_hex = std::fs::read_to_string(&key_path)
        .unwrap()
        .trim()
        .to_string();

    let secret = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA";
    assert!(
        !scrubbed.windows(secret.len()).any(|w| w == secret),
        "scrubbed output must not contain the original secret key"
    );

    let mut unscrub_child = Command::new(bin())
        .args(["restore", "--entries", entries_path.to_str().unwrap()])
        .env("DOPPEL_KEY", &key_hex)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    unscrub_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&scrubbed)
        .unwrap();
    drop(unscrub_child.stdin.take());
    let unscrub_out = unscrub_child.wait_with_output().unwrap();
    assert!(
        unscrub_out.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&unscrub_out.stderr)
    );
    assert_eq!(
        unscrub_out.stdout, payload,
        "E2E round-trip: restored output must match original"
    );

    cleanup(&[&patterns_path, &entries_path, &key_path]);
}

// INV-20: missing DOPPEL_KEY → non-zero exit
#[test]
fn test_e2e_restore_missing_env_var_fails() {
    let entries_path = tmp_path("entries-missing.json");
    std::fs::write(&entries_path, b"[]").unwrap();
    let output = Command::new(bin())
        .args(["restore", "--entries", entries_path.to_str().unwrap()])
        .env_remove("DOPPEL_KEY")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "INV-20: missing DOPPEL_KEY must cause non-zero exit"
    );
    cleanup(&[&entries_path]);
}

#[test]
fn test_e2e_init_creates_patterns_file() {
    let path = tmp_path("init-test-secrets.toml");
    let _ = std::fs::remove_file(&path);

    let output = Command::new(bin())
        .args(["init", "--patterns", path.to_str().unwrap()])
        .output()
        .expect("failed to run init");

    assert!(output.status.success(), "init must succeed");
    assert!(path.exists(), "patterns file must be created");

    let content = std::fs::read_to_string(&path).unwrap();
    let val: toml::Value = content.parse().unwrap();
    assert_eq!(val["version"].as_integer(), Some(2));
    let structural = val["structural"].as_array().unwrap();
    assert!(
        structural.len() >= 15,
        "init must produce at least 15 built-in structural patterns"
    );
    let registered = val["registered"].as_array().unwrap();
    assert!(registered.is_empty());

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
    let path = tmp_path("init-existing-secrets.toml");
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
    let path = tmp_path("init-force-secrets.toml");
    std::fs::write(&path, b"garbage").unwrap();

    let output = Command::new(bin())
        .args(["init", "--patterns", path.to_str().unwrap(), "--force"])
        .output()
        .expect("failed to run init");

    assert!(output.status.success(), "init --force must succeed");
    let content = std::fs::read_to_string(&path).unwrap();
    let val: toml::Value = content.parse().unwrap();
    assert_eq!(val["version"].as_integer(), Some(2));

    cleanup(&[&path]);
}

#[test]
fn test_e2e_swap_missing_patterns_file() {
    let entries_path = tmp_path("entries-missing-pat.json");
    let key_path = tmp_path("key-missing-pat.txt");

    let output = Command::new(bin())
        .args([
            "swap",
            "--patterns",
            "/tmp/nonexistent-secrets-file.toml",
            "--entries",
            entries_path.to_str().unwrap(),
            "--key-out",
            key_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run swap");

    assert!(
        !output.status.success(),
        "swap must fail with missing patterns file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("No such file"),
        "error must mention file not found: {stderr}"
    );

    cleanup(&[&entries_path, &key_path]);
}

#[test]
fn test_e2e_swap_corrupt_patterns_file() {
    let patterns_path = tmp_path("corrupt-secrets.toml");
    std::fs::write(&patterns_path, b"not valid json").unwrap();
    let entries_path = tmp_path("entries-corrupt.json");
    let key_path = tmp_path("key-corrupt.txt");

    let output = Command::new(bin())
        .args([
            "swap",
            "--patterns",
            patterns_path.to_str().unwrap(),
            "--entries",
            entries_path.to_str().unwrap(),
            "--key-out",
            key_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run swap");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "error must indicate invalid patterns: {stderr}"
    );

    cleanup(&[&patterns_path, &entries_path, &key_path]);
}

#[test]
fn test_e2e_register_round_trip() {
    let patterns_path = create_test_patterns_file("register-rt");
    let entries_path = tmp_path("entries-register-rt.json");
    let key_path = tmp_path("key-register-rt.txt");
    let secret = b"my-custom-api-token-that-is-long-enough-for-test";

    let mut register_child = Command::new(bin())
        .args([
            "register",
            "--patterns",
            patterns_path.to_str().unwrap(),
            "--label",
            "my-token-label",
        ])
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

    let payload = [b"token: ".as_slice(), secret, b" end"].concat();
    let mut scrub_child = Command::new(bin())
        .args([
            "swap",
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
        .expect("failed to start swap");
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
        "swap failed: {}",
        String::from_utf8_lossy(&scrub_out.stderr)
    );

    let scrubbed = &scrub_out.stdout;
    assert!(
        !scrubbed.windows(secret.len()).any(|w| w == secret),
        "scrubbed output must not contain original secret"
    );

    let key_hex = std::fs::read_to_string(&key_path)
        .unwrap()
        .trim()
        .to_string();
    let mut unscrub_child = Command::new(bin())
        .args(["restore", "--entries", entries_path.to_str().unwrap()])
        .env("DOPPEL_KEY", &key_hex)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start restore");
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
        "restore failed: {}",
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
        .args(["register", "--patterns", "/tmp/nonexistent-register.toml"])
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
        .args([
            "register",
            "--patterns",
            patterns_path.to_str().unwrap(),
            "--label",
            "test-label",
        ])
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

#[test]
fn test_e2e_inv13_cross_run_fake_stability() {
    // INV-13: Two separate swap invocations with the same patterns file
    // and same secret must produce the same fake.
    let patterns_path = create_test_patterns_file("inv13-cross");
    let entries1_path = tmp_path("entries-inv13-1.json");
    let key1_path = tmp_path("key-inv13-1.txt");
    let entries2_path = tmp_path("entries-inv13-2.json");
    let key2_path = tmp_path("key-inv13-2.txt");

    let payload = b"Authorization: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA end";

    for (ep, kp) in [(&entries1_path, &key1_path), (&entries2_path, &key2_path)] {
        let mut child = Command::new(bin())
            .args([
                "swap",
                "--patterns",
                patterns_path.to_str().unwrap(),
                "--entries",
                ep.to_str().unwrap(),
                "--key-out",
                kp.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(payload).unwrap();
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "swap failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let e1_data = std::fs::read(&entries1_path).unwrap();
    let e2_data = std::fs::read(&entries2_path).unwrap();
    let e1: serde_json::Value = serde_json::from_slice(&e1_data).unwrap();
    let e2: serde_json::Value = serde_json::from_slice(&e2_data).unwrap();

    assert_eq!(
        e1.as_array().unwrap().len(),
        1,
        "first run must detect one secret"
    );
    assert_eq!(
        e2.as_array().unwrap().len(),
        1,
        "second run must detect one secret"
    );
    assert_eq!(
        e1[0]["fake"], e2[0]["fake"],
        "INV-13: same secret + same patterns file must produce same fake across runs"
    );

    cleanup(&[
        &patterns_path,
        &entries1_path,
        &key1_path,
        &entries2_path,
        &key2_path,
    ]);
}
