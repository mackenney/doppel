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
        // NO --key flag — INV-20: key via ITS_CLASSIFIED_KEY env var only
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

fn run_scrub(
    patterns_path: &Path,
    entries_path: &Path,
    key_out_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{PatternsFile, scrub, types::Entry};
    use std::io::{self, Read, Write};

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

    let pf = PatternsFile::deserialize(&file_data)
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    let patterns = pf.into_patterns().map_err(|e| {
        format!(
            "failed to load patterns from {}: {}",
            patterns_path.display(),
            e
        )
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

fn run_init(patterns_path: &Path, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::PatternsFile;

    let mut pf = PatternsFile::new();
    pf.generate_missing_tier1_salts();
    let data = pf.serialize()?;

    write_patterns_file(patterns_path, &data, !force).map_err(|e| -> Box<dyn std::error::Error> {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "patterns file already exists: {}\n  Use --force to overwrite (WARNING: regenerates all salts; existing fakes become invalid)",
                patterns_path.display()
            ).into()
        } else {
            e.into()
        }
    })?;

    eprintln!(
        "created patterns file: {} (15 Tier 1 classes, 0 Tier 2 entries)",
        patterns_path.display()
    );

    Ok(())
}

fn run_register(
    patterns_path: &Path,
    preserve_prefix: usize,
    preserve_suffix: usize,
    restrict_charset: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{PatternsFile, RegistrationOptions, register_with_options};
    use std::io::Read;

    let mut secret = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut *secret)?;

    if secret.is_empty() {
        return Err("no secret provided on stdin".into());
    }

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
    write_patterns_file(patterns_path, &data, false)?;

    let variable_len = secret.len() - preserve_prefix - preserve_suffix;
    eprintln!(
        "registered 1 Tier 2 secret (variable portion: {} bytes)",
        variable_len
    );

    Ok(())
}

fn write_patterns_file(path: &Path, data: &[u8], create_exclusive: bool) -> std::io::Result<()> {
    use std::io::Write;

    if create_exclusive {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // INV-21 equivalent: O_CREAT|O_EXCL is atomic — fails if file exists
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(data)?;
        }
        #[cfg(not(unix))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            file.write_all(data)?;
        }
    } else {
        // Write to a .tmp sibling then rename (atomic on POSIX same-filesystem)
        let tmp = path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(data)?;
            // mode(0o600) only applies to new inodes; set explicitly for existing files
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, data)?;
        }
        std::fs::rename(&tmp, path)?;
    }

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
            .create_new(true) // INV-21: O_EXCL ensures mode applies to a fresh inode
            .mode(0o600)
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
        } => run_register(
            &patterns,
            preserve_prefix,
            preserve_suffix,
            restrict_charset,
        ),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
