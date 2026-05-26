use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "its-classified",
    about = "Secret scrubbing for LLM request/response cycles"
)]
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

fn run_scrub(entries_path: &Path, key_out_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{scrub, tier1::patterns, types::Entry};
    use std::io::{self, Read, Write};

    let mut payload = Vec::new();
    io::stdin().read_to_end(&mut payload)?;

    let result = scrub(&payload, &patterns::all())?;

    io::stdout().write_all(&result.payload)?;

    let entries_json = Entry::serialize_entries(&result.entries)?;
    std::fs::write(entries_path, &entries_json)?;

    write_key_file(key_out_path, result.session_key.as_bytes())?;

    Ok(())
}

fn write_key_file(path: &Path, key_bytes: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write;

    let hex_key = hex_encode(key_bytes);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // INV-21: MUST be 0600
            .open(path)?;
        file.write_all(hex_key.as_bytes())?;
        file.write_all(b"\n")?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::File::create(path)?;
        file.write_all(hex_key.as_bytes())?;
        file.write_all(b"\n")?;
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn run_unscrub(entries_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{
        types::{Entry, SessionKey},
        unscrub,
    };
    use std::io;

    // INV-20: session key ONLY via ITS_CLASSIFIED_KEY env var
    let key_hex = std::env::var("ITS_CLASSIFIED_KEY")
        .map_err(|_| "ITS_CLASSIFIED_KEY environment variable not set")?;
    let key_bytes = hex_decode(&key_hex).map_err(|_| "ITS_CLASSIFIED_KEY is not valid hex")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "ITS_CLASSIFIED_KEY must be 64 hex characters (32 bytes)")?;
    let session_key = SessionKey::from_bytes(key_array);

    let entries_data = std::fs::read(entries_path)?;
    let entries = Entry::deserialize_entries(&entries_data)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    unscrub(
        &mut stdin.lock(),
        &mut stdout.lock(),
        &entries,
        &session_key,
    )?;

    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

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
