// Spec: SPEC.md §Behavioral Invariants (INV-30, INV-31, INV-34)

use std::process::Command;

fn cli_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_doppel"))
}

fn init_patterns(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("secrets.toml");
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
    // INV-30: user-defined structural pattern MUST have at least one Variable segment
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
            "literal:prefix_",
            "--segment",
            "variable:alphanumeric:10:10",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "first define failed");

    let output = cli_bin()
        .args(["define", "--patterns"])
        .arg(&pat)
        .args([
            "--identifier",
            "MY_PAT",
            "--segment",
            "literal:other_",
            "--segment",
            "variable:digits:5:5",
        ])
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
        .args(["--anchor-len", "3"])
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
            "literal:prefix_",
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
    assert!(stdout.contains("Patterns:"), "stdout: {stdout}");
    assert!(stdout.contains("anthropic"), "stdout: {stdout}");
    assert!(stdout.contains("[family]"), "stdout: {stdout}");
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

#[test]
fn test_inspect_shows_digest_count() {
    // SPEC §CLI Contract: inspect MUST output digest count
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
    assert!(
        stdout.contains("Digests:"),
        "inspect must show digest count; stdout: {stdout}"
    );
    let digest_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("Digests:")).collect();
    assert_eq!(digest_lines.len(), 1, "exactly one Digests: line");
    // anthropic is a family pattern — 0 digests
    assert!(
        digest_lines[0].contains('0'),
        "family pattern must show 0 digests; line: {}",
        digest_lines[0]
    );
}

#[test]
fn test_inspect_shows_entropy_for_variable_segments() {
    // SPEC §CLI Contract: inspect MUST output entropy estimate for variable portions
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
    assert!(
        stdout.contains("bits"),
        "inspect must show entropy estimate in bits for variable segments; stdout: {stdout}"
    );
}

#[test]
fn test_list_shows_digest_count() {
    // SPEC §CLI Contract: list MUST output digest count per entry
    let dir = tempfile::tempdir().unwrap();
    let pat = init_patterns(dir.path());
    let output = cli_bin()
        .args(["list", "--patterns"])
        .arg(&pat)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Built-in family patterns have 0 digests — output must contain the count
    assert!(
        stdout.contains("digests"),
        "list must show digest count per entry; stdout: {stdout}"
    );
}

#[test]
fn test_inv37_register_preserves_comments() {
    // INV-37: register MUST preserve existing comments in the patterns file
    use std::fs;
    use std::io::Write;
    use std::process::Stdio;

    let dir = tempfile::tempdir().unwrap();
    let pat = dir.path().join("secrets.toml");

    // A minimal valid patterns file with a recognisable sentinel comment.
    let initial = "# sentinel-comment-for-inv37\nversion = 3\npattern = []\n";
    fs::write(&pat, initial).unwrap();

    // Secret must be long enough to clear the 83-bit entropy threshold.
    let secret = b"my-test-secret-value-that-is-long-enough-for-entropy";

    let mut child = cli_bin()
        .args(["register", "--patterns"])
        .arg(&pat)
        .args(["--identifier", "inv37-entry"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    child.stdin.take().unwrap().write_all(secret).unwrap();

    let status = child.wait_with_output().unwrap().status;
    assert!(status.success(), "register failed");

    let after = fs::read_to_string(&pat).unwrap();
    assert!(
        after.contains("# sentinel-comment-for-inv37"),
        "INV-37: register must preserve existing comments; got:\n{after}"
    );
}

#[test]
fn test_inv37_register_group_preserves_inline_comments() {
    // INV-37: the --group path of `register` must preserve inline comments inside
    // the updated [[pattern]] block. This exercises the round-4 in-place TOML surgery
    // code path (doc["pattern"].as_array_of_tables_mut() → arr.push), not the first-
    // registration path tested by test_inv37_register_preserves_comments.
    use std::fs;
    use std::io::Write;
    use std::process::Stdio;

    let dir = tempfile::tempdir().unwrap();
    let pat = dir.path().join("secrets.toml");

    // Patterns file with one instance pattern entry containing an inline sentinel comment.
    // The comment must survive a `register --group` update to this entry.
    let initial = concat!(
        "# file-level-comment\n",
        "version = 3\n",
        "[[pattern]]\n",
        "# sentinel-inside-entry\n",
        "identifier = \"grp-inv37\"\n",
        "salt = \"0000000000000000000000000000000000000000000000000000000000000001\"\n",
        "digests = [\"aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233\"]\n",
        "[[pattern.segments]]\n",
        "type = \"opaque\"\n",
        "value = \"pfx_\"\n",
        "[[pattern.segments]]\n",
        "type = \"variable\"\n",
        "charset = \"alphanumeric\"\n",
        "min = 20\n",
        "max = 20\n",
    );
    fs::write(&pat, initial).unwrap();

    // The --group path calls add_secret_to_group which has no entropy gate; any
    // non-empty secret is accepted. Use a long secret to match the group pattern shape.
    let secret = b"inv37-group-second-secret-long-enough-for-entropy-threshold";

    let mut child = cli_bin()
        .args(["register", "--patterns"])
        .arg(&pat)
        .args(["--group", "grp-inv37"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(secret).unwrap();
    let status = child.wait_with_output().unwrap().status;
    assert!(status.success(), "register --group failed");

    let after = fs::read_to_string(&pat).unwrap();
    assert!(
        after.contains("# sentinel-inside-entry"),
        "INV-37: --group must preserve inline comments inside the updated entry; got:\n{after}"
    );
    assert!(
        after.contains("# file-level-comment"),
        "INV-37: --group must preserve file-level comments; got:\n{after}"
    );
    // The updated entry must have two digests (original + newly added).
    let pf = doppel::SecretsFile::deserialize(after.as_bytes()).unwrap();
    let entry = pf
        .pattern
        .iter()
        .find(|e| e.identifier == "grp-inv37")
        .unwrap();
    assert_eq!(entry.digests.len(), 2, "--group must add a second digest");
}

#[test]
fn test_vc16_remove_eliminates_identifier() {
    // VC-16: After `remove` succeeds on an existing identifier, the patterns file
    // MUST NOT contain any entry with that identifier.
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let pat = dir.path().join("secrets.toml");

    // File with two family pattern entries; remove one and verify it is gone.
    let initial = concat!(
        "version = 3\n",
        "[[pattern]]\n",
        "identifier = \"keep-me\"\n",
        "salt = \"0000000000000000000000000000000000000000000000000000000000000001\"\n",
        "digests = []\n",
        "[[pattern.segments]]\n",
        "type = \"literal\"\n",
        "value = \"pfx_\"\n",
        "[[pattern.segments]]\n",
        "type = \"variable\"\n",
        "charset = \"alphanumeric\"\n",
        "min = 10\n",
        "max = 20\n",
        "[[pattern]]\n",
        "identifier = \"remove-me\"\n",
        "salt = \"0000000000000000000000000000000000000000000000000000000000000002\"\n",
        "digests = []\n",
        "[[pattern.segments]]\n",
        "type = \"literal\"\n",
        "value = \"pre_\"\n",
        "[[pattern.segments]]\n",
        "type = \"variable\"\n",
        "charset = \"alphanumeric\"\n",
        "min = 10\n",
        "max = 20\n",
    );
    fs::write(&pat, initial).unwrap();

    let output = cli_bin()
        .args(["remove", "--patterns"])
        .arg(&pat)
        .args(["--identifier", "remove-me"])
        .output()
        .unwrap();
    assert!(output.status.success(), "remove must succeed");

    let after = fs::read_to_string(&pat).unwrap();
    let pf = doppel::SecretsFile::deserialize(after.as_bytes()).unwrap();
    assert!(
        pf.pattern.iter().all(|e| e.identifier != "remove-me"),
        "VC-16: removed identifier must not appear in the file"
    );
    assert!(
        pf.pattern.iter().any(|e| e.identifier == "keep-me"),
        "VC-16: other entries must be preserved"
    );
}
