// Spec: SPEC.md §Behavioral Invariants (INV-30, INV-31, INV-34)

use std::process::Command;

fn cli_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_its-classified"))
}

fn init_patterns(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("patterns.toml");
    let output = cli_bin()
        .args(["init", "--patterns"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

#[test]
fn test_inv30_define_rejects_pure_literal_segments() {
    // INV-30: user-defined Tier 1 MUST have at least one Variable segment
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let output = cli_bin()
        .args(["define", "--patterns"])
        .arg(&pat)
        .args(["--identifier", "NO_VAR", "--segment", "literal:only-fixed"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at least one variable segment"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_inv31_define_rejects_duplicate_identifier() {
    // INV-31: identifier MUST be unique within the patterns file
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let output = cli_bin()
        .args(["define", "--patterns"])
        .arg(&pat)
        .args([
            "--identifier",
            "MY_PAT",
            "--segment",
            "variable:alphanumeric:10:10",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "first define failed");

    let output = cli_bin()
        .args(["define", "--patterns"])
        .arg(&pat)
        .args(["--identifier", "MY_PAT", "--segment", "variable:digits:5:5"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("duplicate") || stderr.contains("already exists"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_inv34_list_does_not_modify_file() {
    // INV-34: read-only commands MUST NOT modify the patterns file
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let before = std::fs::read(&pat).unwrap();

    let output = cli_bin()
        .args(["list", "--patterns"])
        .arg(&pat)
        .output()
        .unwrap();
    assert!(output.status.success());

    let after = std::fs::read(&pat).unwrap();
    assert_eq!(before, after, "list modified the patterns file");
}

#[test]
fn test_inv34_inspect_does_not_modify_file() {
    // INV-34: read-only commands MUST NOT modify the patterns file
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let before = std::fs::read(&pat).unwrap();

    let output = cli_bin()
        .args(["inspect", "--patterns"])
        .arg(&pat)
        .args(["--identifier", "anthropic"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let after = std::fs::read(&pat).unwrap();
    assert_eq!(before, after, "inspect modified the patterns file");
}

#[test]
fn test_register_requires_label() {
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let output = cli_bin()
        .args(["register", "--patterns"])
        .arg(&pat)
        .args(["--preserve-prefix", "0", "--preserve-suffix", "0"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "register without --label should fail"
    );
}

#[test]
fn test_define_rejects_unknown_charset() {
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let output = cli_bin()
        .args(["define", "--patterns"])
        .arg(&pat)
        .args([
            "--identifier",
            "BAD",
            "--segment",
            "variable:bogus_charset:5:5",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown charset"), "stderr: {stderr}");
}

#[test]
fn test_list_shows_all_entries() {
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let output = cli_bin()
        .args(["list", "--patterns"])
        .arg(&pat)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Tier 1 patterns:"), "stdout: {stdout}");
    assert!(stdout.contains("anthropic"), "stdout: {stdout}");
    assert!(stdout.contains("Tier 2 secrets:"), "stdout: {stdout}");
}

#[test]
fn test_inspect_shows_salt_fingerprint_not_full_salt() {
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let output = cli_bin()
        .args(["inspect", "--patterns"])
        .arg(&pat)
        .args(["--identifier", "anthropic"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Salt:"), "stdout: {stdout}");
    assert!(stdout.contains("..."), "salt should be truncated with ...");
    let lines: Vec<&str> = stdout.lines().filter(|l| l.contains("Salt:")).collect();
    assert_eq!(lines.len(), 1);
    let salt_line = lines[0];
    let salt_part = salt_line.split("Salt:").nth(1).unwrap().trim();
    assert!(
        salt_part.len() < 20,
        "salt fingerprint too long: {salt_part}"
    );
}
