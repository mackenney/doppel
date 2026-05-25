use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_its-classified"))
}

fn tmp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "its-classified-e2e-{}-{}",
        name,
        std::process::id()
    ))
}

fn cleanup(paths: &[&PathBuf]) {
    for p in paths {
        let _ = std::fs::remove_file(p);
    }
}

// VC-8 / INV-21: scrub creates session key file with mode 0600
#[test]
fn test_e2e_key_file_mode_0600() {
    let entries_path = tmp_path("entries.json");
    let key_path = tmp_path("key.txt");

    let mut child = Command::new(bin())
        .args([
            "scrub",
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
    assert!(
        !help_text.contains("--key "),
        "INV-20: --key flag must not appear in unscrub --help"
    );
    assert!(
        !help_text.to_lowercase().contains("--key-file"),
        "INV-20: --key-file must not appear in unscrub --help"
    );
}

// VC-9: unscrub writes to stdout before stdin reaches EOF (streaming)
#[test]
fn test_e2e_unscrub_streams_before_eof() {
    use std::io::Read;
    use std::thread;

    let entries_path = tmp_path("entries-stream.json");
    let key_path = tmp_path("key-stream.txt");
    let payload = b"Hello, world! No secrets here.";

    let mut scrub_child = Command::new(bin())
        .args([
            "scrub",
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

    let writer = thread::spawn(move || {
        stdin.write_all(&first_half).unwrap();
        thread::sleep(std::time::Duration::from_millis(50));
        stdin.write_all(&second_half).unwrap();
    });

    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    writer.join().unwrap();

    let status = unscrub_child.wait().unwrap();
    assert!(status.success(), "unscrub failed");
    assert_eq!(
        output, payload,
        "VC-9: round-trip output must match original"
    );

    cleanup(&[&entries_path, &key_path]);
}

// Full E2E round-trip: scrub + unscrub at process boundary
#[test]
fn test_e2e_full_round_trip() {
    let entries_path = tmp_path("entries-rt.json");
    let key_path = tmp_path("key-rt.txt");

    let payload = b"Authorization: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA end";

    let mut scrub_child = Command::new(bin())
        .args([
            "scrub",
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
        "scrub failed: {}",
        String::from_utf8_lossy(&scrub_out.stderr)
    );
    let scrubbed = scrub_out.stdout;
    let key_hex = std::fs::read_to_string(&key_path)
        .unwrap()
        .trim()
        .to_string();

    assert!(
        !scrubbed
            .windows(b"sk-ant-api03-AAAA".len())
            .any(|w| w.starts_with(b"sk-ant-api03-AAAA")),
        "scrubbed output must not contain original key pattern"
    );

    let mut unscrub_child = Command::new(bin())
        .args(["unscrub", "--entries", entries_path.to_str().unwrap()])
        .env("ITS_CLASSIFIED_KEY", &key_hex)
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
        "unscrub failed: {}",
        String::from_utf8_lossy(&unscrub_out.stderr)
    );
    assert_eq!(
        unscrub_out.stdout, payload,
        "E2E round-trip: restored output must match original"
    );

    cleanup(&[&entries_path, &key_path]);
}

// INV-20: missing ITS_CLASSIFIED_KEY → non-zero exit
#[test]
fn test_e2e_unscrub_missing_env_var_fails() {
    let entries_path = tmp_path("entries-missing.json");
    std::fs::write(&entries_path, b"[]").unwrap();
    let output = Command::new(bin())
        .args(["unscrub", "--entries", entries_path.to_str().unwrap()])
        .env_remove("ITS_CLASSIFIED_KEY")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "INV-20: missing ITS_CLASSIFIED_KEY must cause non-zero exit"
    );
    cleanup(&[&entries_path]);
}
