# Step 08: CLI Binary

## Context

### Overall Objective
Build `its-classified`: secret scrubbing and streaming restoration.

### Phase Context
Wave 5 (sequential after step-07). Wraps the library in a command-line interface.
The CLI exposes `scrub` and `unscrub` as subcommands. This step enforces INV-20
(session key via env var only) and INV-21 (0600 key file mode).

### This Step
Implement `src/main.rs` using `clap` derive. Subcommands: `scrub` (reads stdin, writes
stdout + entries file + key file), `unscrub` (reads ITS_CLASSIFIED_KEY env var, reads
entries file, streams stdin → stdout). The key file MUST be created with mode 0600.
No `--key` flag on `unscrub`.

## Prerequisites

- Step 06 complete (scrub() works)
- Step 07 complete (unscrub() works)

## Files to Read Before Starting

- `src/main.rs` — current stub
- `SPEC.md §CLI Contract` — exact requirements
- `SPEC.md INV-20, INV-21` — env var and file mode requirements

## Implementation

### Task 1: Clap CLI structure

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "its-classified", about = "Secret scrubbing for LLM request/response cycles")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scrub secrets from stdin. Writes scrubbed payload to stdout.
    Scrub {
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
        // NO --key flag — INV-20: key via ITS_CLASSIFIED_KEY env var only
    },
}
```

### Task 2: scrub subcommand implementation

```rust
fn run_scrub(entries_path: &Path, key_out_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{scrub, tier1::patterns, types::Entry};
    use std::io::{self, Read};

    // Read complete payload from stdin (scrub takes a complete buffer)
    let mut payload = Vec::new();
    io::stdin().read_to_end(&mut payload)?;

    // Scrub with all built-in patterns
    let result = scrub(&payload, &patterns::all());

    // Write scrubbed payload to stdout
    io::stdout().write_all(&result.payload)?;

    // Write entries to file (JSON, base64-encoded binary fields)
    let entries_json = Entry::serialize_entries(&result.entries)?;
    std::fs::write(entries_path, &entries_json)?;

    // Write session key to file with mode 0600 (INV-21)
    write_key_file(key_out_path, result.session_key.as_bytes())?;

    Ok(())
}
```

### Task 3: Key file creation with 0600 mode (INV-21)

```rust
fn write_key_file(path: &Path, key_bytes: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write;

    // Encode as hex for human readability and easy env var passing
    let hex_key = hex_encode(key_bytes);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)  // INV-21: MUST be 0600
            .open(path)?;
        file.write_all(hex_key.as_bytes())?;
        file.write_all(b"\n")?;
    }

    #[cfg(not(unix))]
    {
        // Non-Unix: write without explicit permissions (best effort)
        // Document: 0600 enforcement is Unix-only
        let mut file = std::fs::File::create(path)?;
        file.write_all(hex_key.as_bytes())?;
        file.write_all(b"\n")?;
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
```

**Note**: `SessionKey` needs a way to expose its bytes for CLI serialization without
implementing `Display` or `Debug`. Add `pub(crate) fn as_bytes(&self) -> &[u8; 32]`
to `SessionKey` (already specified in step-02 task — ensure it exists). The CLI is
in the same crate as the library (`src/main.rs` is a binary target of the same crate),
so `pub(crate)` methods are accessible.

### Task 4: unscrub subcommand implementation

```rust
fn run_unscrub(entries_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{unscrub, types::{Entry, SessionKey}};
    use std::io;

    // INV-20: session key ONLY via ITS_CLASSIFIED_KEY env var
    let key_hex = std::env::var("ITS_CLASSIFIED_KEY")
        .map_err(|_| "ITS_CLASSIFIED_KEY environment variable not set")?;
    let key_bytes = hex_decode(&key_hex)
        .map_err(|_| "ITS_CLASSIFIED_KEY is not valid hex")?;
    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "ITS_CLASSIFIED_KEY must be 64 hex characters (32 bytes)")?;
    let session_key = SessionKey::from_bytes(key_array);

    // Read entries from file
    let entries_data = std::fs::read(entries_path)?;
    let entries = Entry::deserialize_entries(&entries_data)?;

    // Stream stdin → stdout (INV-8: streaming, not buffering)
    let stdin = io::stdin();
    let stdout = io::stdout();
    unscrub(&mut stdin.lock(), &mut stdout.lock(), &entries, &session_key)?;

    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 { return Err(()); }
    s.as_bytes().chunks(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).map_err(|_| ())
    }).collect()
}
```

### Task 5: main() entry point

```rust
fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scrub { entries, key_out } => run_scrub(&entries, &key_out),
        Commands::Unscrub { entries } => run_unscrub(&entries),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
```

### Task 6: SessionKey hex export (add to src/types.rs if not present)

The CLI needs access to raw key bytes for writing the key file. Add to `SessionKey`:

```rust
impl SessionKey {
    // Already defined in step-02: pub(crate) fn as_bytes(&self) -> &[u8; 32]
    // Also add:
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self { Self(Box::new(bytes)) }
}
```

If `from_bytes` is not already `pub` (only `pub(crate)`), the CLI binary (which is in
the same crate) can use it. No change needed.

## Acceptance Criteria

- [ ] `cargo build` exits 0
- [ ] `echo "hello world" | cargo run -- scrub --entries /tmp/test-entries.json --key-out /tmp/test-key.txt` exits 0
- [ ] `stat -c %a /tmp/test-key.txt` outputs `600` (on Linux)
- [ ] `its-classified unscrub --help` output does NOT contain `--key` anywhere
- [ ] `its-classified scrub --help` shows `--entries` and `--key-out` flags
- [ ] `ITS_CLASSIFIED_KEY=$(cat /tmp/test-key.txt) its-classified unscrub --entries /tmp/test-entries.json < /tmp/scrubbed.txt` exits 0
- [ ] `cargo clippy -- -D warnings` exits 0

## Reviewer Instructions

You are reviewing Step 08. Verify:

1. Run `cargo build` — must exit 0
2. Run `cargo clippy -- -D warnings` — must exit 0
3. Run `its-classified unscrub --help` — confirm `--key` does NOT appear in output (INV-20)
4. Run a scrub command: `echo "test" | its-classified scrub --entries /tmp/e.json --key-out /tmp/k.txt`
5. Run `stat -c %a /tmp/k.txt` — must output `600` (INV-21)
6. Inspect `src/main.rs`: confirm `ITS_CLASSIFIED_KEY` is the ONLY way to supply the key in `run_unscrub`

Report: "PASS" or "FAIL: <criterion> — <detail>"

## Rollback

`git revert` step-08 commit.
