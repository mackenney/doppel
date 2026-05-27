fn init_patterns_file(path: &std::path::Path) {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_its-classified"))
        .args(["init", "--patterns", path.to_str().unwrap(), "--force"])
        .status()
        .expect("failed to run init");
    assert!(status.success(), "init failed");
}

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
        let patterns_path = dir.path().join("patterns.json");
        let entries_path = dir.path().join("entries.json");
        let key_path = dir.path().join("key.txt");
        init_patterns_file(&patterns_path);
        let payload = b"no secrets here";
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_its-classified"))
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
        let patterns_path = dir.path().join("patterns.json");
        let entries_path = dir.path().join("entries.json");
        let key_path = dir.path().join("key.txt");
        init_patterns_file(&patterns_path);

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
                "--patterns",
                patterns_path.to_str().unwrap(),
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
