# Step 09: CLI Surface — `init`, `register`, and `--patterns`

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 5. Depends on step-08 (patterns_file module provides `PatternsFile`, `serialize`/`deserialize`, `into_patterns`, `add_tier2_pattern`, `generate_missing_tier1_salts`). This step adds the CLI subcommands and flags that make the library's patterns file support user-accessible.

### This Step
Add three CLI changes: (1) `init` subcommand that creates a default patterns file, (2) `register` subcommand that reads a secret from stdin and appends a Tier 2 entry, (3) `--patterns <FILE>` required flag on `scrub` that loads the patterns file instead of hardcoding `patterns::all()`. The `unscrub` command is unchanged.

## Prerequisites
- Step 08 complete (provides `PatternsFile` and all its methods)

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/cli/src/main.rs` — full file, 149 lines
- `/home/ignacio/pr/its-classified/cli/Cargo.toml` — dependencies

## Implementation

### Task 1: Add `Init` and `Register` variants to `Commands` enum

In `cli/src/main.rs`, locate the `Commands` enum (line 15). Add two new variants after `Unscrub`:

```rust
#[derive(Subcommand)]
enum Commands {
    /// Scrub secrets from stdin. Writes scrubbed payload to stdout.
    Scrub {
        /// Path to the patterns file (created by `init`).
        #[arg(long)]
        patterns: PathBuf,
        /// Path to write the entries file (ciphertext; not sensitive).
        #[arg(long)]
        entries: PathBuf,
        /// Path to write the session key file (sensitive; created with mode 0600).
        #[arg(long = "key-out")]
        key_out: PathBuf,
    },
    /// Restore secrets in a response stream from stdin to stdout.
    /// Session key must be provided via the ITS_CLASSIFIED_KEY environment variable.
    Unscrub {
        /// Path to the entries file written by scrub.
        #[arg(long)]
        entries: PathBuf,
    },
    /// Create a new patterns file with all built-in Tier 1 definitions and stable salts.
    Init {
        /// Path to create the patterns file.
        #[arg(long)]
        patterns: PathBuf,
        /// Overwrite if file exists (WARNING: regenerates all salts; existing fakes become invalid).
        #[arg(long)]
        force: bool,
    },
    /// Register a Tier 2 secret (read from stdin) into an existing patterns file.
    Register {
        /// Path to the patterns file to update.
        #[arg(long)]
        patterns: PathBuf,
        /// Bytes at start of secret to preserve verbatim in the fake.
        #[arg(long, default_value_t = 0)]
        preserve_prefix: usize,
        /// Bytes at end of secret to preserve verbatim in the fake.
        #[arg(long, default_value_t = 0)]
        preserve_suffix: usize,
        /// Draw fake bytes from the secret's own charset only.
        #[arg(long)]
        restrict_charset: bool,
    },
}
```

Note: `Scrub` variant gains a `patterns: PathBuf` field (first field). This is a breaking change — existing callers must now pass `--patterns`.

### Task 2: Implement `run_init`

Add a new function in `cli/src/main.rs`:

```rust
fn run_init(patterns_path: &Path, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::PatternsFile;

    if patterns_path.exists() && !force {
        return Err(format!(
            "patterns file already exists: {}\n  Use --force to overwrite (WARNING: regenerates all salts; existing fakes become invalid)",
            patterns_path.display()
        ).into());
    }

    let mut pf = PatternsFile::new();
    pf.generate_missing_tier1_salts();
    let data = pf.serialize()?;

    write_patterns_file(patterns_path, &data)?;

    eprintln!(
        "created patterns file: {} (8 Tier 1 classes, 0 Tier 2 entries)",
        patterns_path.display()
    );

    Ok(())
}
```

### Task 3: Implement `write_patterns_file` helper

Add a helper function for writing patterns files with 0600 permissions:

```rust
fn write_patterns_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }

    Ok(())
}
```

### Task 4: Implement `run_register`

Add a new function:

```rust
fn run_register(
    patterns_path: &Path,
    preserve_prefix: usize,
    preserve_suffix: usize,
    restrict_charset: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{PatternsFile, RegistrationOptions, register_with_options};
    use std::io::Read;

    // Read secret from stdin (raw bytes, no trimming)
    let mut secret = Vec::new();
    std::io::stdin().read_to_end(&mut secret)?;

    if secret.is_empty() {
        return Err("no secret provided on stdin".into());
    }

    // Load existing patterns file
    let file_data = std::fs::read(patterns_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "patterns file not found: {}\n  tip: create it with: its-classified init --patterns {}",
                patterns_path.display(),
                patterns_path.display()
            )
        } else {
            format!("failed to read patterns file: {}", e)
        }
    })?;

    let mut pf = PatternsFile::deserialize(&file_data)?;

    let opts = RegistrationOptions {
        preserve_prefix,
        preserve_suffix,
        restrict_charset,
    };
    let pattern = register_with_options(&secret, &opts)?;
    pf.add_tier2_pattern(&pattern)?;

    let data = pf.serialize()?;
    write_patterns_file(patterns_path, &data)?;

    let variable_len = secret.len() - preserve_prefix - preserve_suffix;
    eprintln!(
        "registered 1 Tier 2 secret (variable portion: {} bytes)",
        variable_len
    );

    Ok(())
}
```

### Task 5: Update `run_scrub` to load patterns from file

Replace the `run_scrub` function signature and body:

```rust
fn run_scrub(
    patterns_path: &Path,
    entries_path: &Path,
    key_out_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{PatternsFile, scrub, types::Entry};
    use std::io::{self, Read, Write};

    // Load patterns file
    let file_data = std::fs::read(patterns_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "patterns file not found: {}\n  tip: create it with: its-classified init --patterns {}",
                patterns_path.display(),
                patterns_path.display()
            )
        } else {
            format!("failed to read patterns file: {}", e)
        }
    })?;

    let pf = PatternsFile::deserialize(&file_data).map_err(|e| {
        format!("invalid patterns file: {}: {}", patterns_path.display(), e)
    })?;

    let patterns = pf.into_patterns().map_err(|e| {
        format!("failed to load patterns from {}: {}", patterns_path.display(), e)
    })?;

    let mut payload = Vec::new();
    io::stdin().read_to_end(&mut payload)?;

    let result = scrub(&payload, &patterns)?;

    io::stdout().write_all(&result.payload)?;

    let entries_json = Entry::serialize_entries(&result.entries)?;
    std::fs::write(entries_path, &entries_json)?;

    write_key_file(key_out_path, result.session_key.as_bytes())?;

    Ok(())
}
```

### Task 6: Update `main()` match arms

Replace the `main()` match block:

```rust
fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scrub {
            patterns,
            entries,
            key_out,
        } => run_scrub(&patterns, &entries, &key_out),
        Commands::Unscrub { entries } => run_unscrub(&entries),
        Commands::Init { patterns, force } => run_init(&patterns, force),
        Commands::Register {
            patterns,
            preserve_prefix,
            preserve_suffix,
            restrict_charset,
        } => run_register(&patterns, preserve_prefix, preserve_suffix, restrict_charset),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
```

### Task 7: Remove unused imports

In `cli/src/main.rs`, remove the `use its_classified::tier1::patterns` import from `run_scrub` (it was `patterns::all()`). The function now uses `PatternsFile::into_patterns` instead.

### Task 8: Verify build

```sh
cargo build -p its-classified-cli
```

The CLI binary should compile. Note: existing e2e tests will fail because they don't pass `--patterns`. That's expected and addressed in step-10.

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `cargo build -p its-classified-cli 2>&1 | grep -c "error"` outputs `0`
- [ ] `cargo run -p its-classified-cli -- init --help 2>&1 | grep -c "patterns"` outputs at least `1`
- [ ] `cargo run -p its-classified-cli -- register --help 2>&1 | grep -c "patterns"` outputs at least `1`
- [ ] `cargo run -p its-classified-cli -- scrub --help 2>&1 | grep -c "patterns"` outputs at least `1`
- [ ] `cargo run -p its-classified-cli -- scrub --help 2>&1 | grep -c "\-\-patterns"` outputs at least `1`
- [ ] `grep -c "patterns::all()" /home/ignacio/pr/its-classified/cli/src/main.rs` outputs `0` (hardcoded patterns removed)
- [ ] `grep -c "fn run_init" /home/ignacio/pr/its-classified/cli/src/main.rs` outputs `1`
- [ ] `grep -c "fn run_register" /home/ignacio/pr/its-classified/cli/src/main.rs` outputs `1`
- [ ] `grep -c "write_patterns_file" /home/ignacio/pr/its-classified/cli/src/main.rs` outputs at least `3`
- [ ] Quick smoke test: `tmpdir=$(mktemp -d) && cargo run -p its-classified-cli -- init --patterns "$tmpdir/p.json" && test -f "$tmpdir/p.json" && echo "init works" && rm -rf "$tmpdir"` outputs `init works`

## Reviewer Instructions

You are reviewing Step 09. Verify:
1. Run `cargo build -p its-classified-cli` — builds with no errors
2. Check `cli/src/main.rs` for:
   - `Commands::Scrub` has `patterns: PathBuf` as first field
   - `Commands::Init` exists with `patterns` and `force` fields
   - `Commands::Register` exists with `patterns`, `preserve_prefix`, `preserve_suffix`, `restrict_charset`
   - `run_scrub` loads patterns from file, not `patterns::all()`
   - `run_init` creates file with `PatternsFile::generate_missing_tier1_salts`
   - `run_register` reads stdin, calls `register_with_options`, calls `add_tier2_pattern`
   - `write_patterns_file` sets mode 0600 on unix
3. Smoke test: `init` creates a valid JSON patterns file
4. Smoke test: `register` with piped secret updates the file
5. Run `cargo clippy -p its-classified-cli 2>&1` — no new warnings
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- cli/src/main.rs cli/Cargo.toml
```
