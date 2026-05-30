use clap::{ArgGroup, Parser, Subcommand};
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
        /// Human-readable label for this secret (unique within the patterns file).
        #[arg(long)]
        label: String,
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
    /// Define a user Tier 1 pattern (structural pattern with named segments).
    Define {
        /// Path to the patterns file to update.
        #[arg(long)]
        patterns: PathBuf,
        /// Unique identifier for this pattern (e.g. MY_API_KEY).
        #[arg(long)]
        identifier: String,
        /// Segment spec: "literal:<value>" or "variable:<charset>:<min>:<max>".
        /// Valid charsets: alphanumeric, url_safe_base64, uppercase_alphanumeric, digits, hex_lower.
        /// Repeat --segment for each segment in order.
        #[arg(long, required = true, num_args = 1)]
        segment: Vec<String>,
    },
    /// List all Tier 1 patterns and Tier 2 secrets in a patterns file.
    List {
        /// Path to the patterns file.
        #[arg(long)]
        patterns: PathBuf,
    },
    /// Show details for a single Tier 1 pattern or Tier 2 secret.
    #[command(group(ArgGroup::new("target").required(true).args(["identifier", "label"])))]
    Inspect {
        /// Path to the patterns file.
        #[arg(long)]
        patterns: PathBuf,
        /// Identifier of the Tier 1 pattern to inspect.
        #[arg(long, group = "target")]
        identifier: Option<String>,
        /// Label of the Tier 2 secret to inspect.
        #[arg(long, group = "target")]
        label: Option<String>,
    },
    /// Remove a Tier 1 pattern or Tier 2 secret from a patterns file.
    #[command(group(ArgGroup::new("target").required(true).args(["identifier", "label"])))]
    Remove {
        /// Path to the patterns file.
        #[arg(long)]
        patterns: PathBuf,
        /// Identifier of the Tier 1 pattern to remove.
        #[arg(long, group = "target")]
        identifier: Option<String>,
        /// Label of the Tier 2 secret to remove.
        #[arg(long, group = "target")]
        label: Option<String>,
    },
}

const INIT_COMMENT_BLOCK: &str = r#"# Tier 2 secrets are registered via the CLI:
#
#   echo -n 'my-secret-value' | its-classified register \
#     --patterns <this-file> \
#     --label my-secret \
#     --preserve-prefix 0 \
#     --preserve-suffix 0
#
# Each [[tier2]] entry contains:
#   label             - human-readable identifier (unique, required by CLI)
#   start_fragment    - first bytes of the secret (hex; detection anchor)
#   end_fragment      - last bytes of the secret (hex; detection anchor)
#   exact_length      - total byte length of the secret
#   hmac_salt         - unique salt for HMAC verification (hex)
#   hmac_digest       - HMAC digest for candidate confirmation (hex)
#   preserve_prefix   - bytes at start preserved verbatim in fake
#   preserve_suffix   - bytes at end preserved verbatim in fake
#   charset           - (optional) byte set for fake generation; omit for wide default
#
# User-defined Tier 1 patterns can be added via:
#
#   its-classified define --patterns <this-file> \
#     --identifier MY_PATTERN \
#     --segment literal:prefix_ \
#     --segment variable:alphanumeric:32:32
#
"#;

fn read_patterns_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(path).map_err(|e| -> Box<dyn std::error::Error> {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "patterns file not found: {}\n  tip: create it with: its-classified init --patterns {}",
                path.display(),
                path.display()
            )
            .into()
        } else {
            format!("failed to read patterns file: {}", e).into()
        }
    })
}

fn run_scrub(
    patterns_path: &Path,
    entries_path: &Path,
    key_out_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{PatternsFile, scrub, types::Entry};
    use std::io::{self, Read, Write};

    let file_data = read_patterns_file(patterns_path)?;

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
    pf.generate_missing_tier1_salts_with_segments();
    let serialized = pf.serialize()?;
    let mut data = INIT_COMMENT_BLOCK.as_bytes().to_vec();
    data.extend_from_slice(&serialized);

    write_patterns_file(patterns_path, &data, !force).map_err(
        |e| -> Box<dyn std::error::Error> {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "patterns file already exists: {}\n  Use --force to overwrite (WARNING: regenerates all salts; existing fakes become invalid)",
                    patterns_path.display()
                )
                .into()
            } else {
                e.into()
            }
        },
    )?;

    let count = pf.tier1.len();
    eprintln!(
        "created patterns file: {} ({} Tier 1 patterns, 0 Tier 2 secrets)",
        patterns_path.display(),
        count
    );

    Ok(())
}

fn run_register(
    patterns_path: &Path,
    label: &str,
    preserve_prefix: usize,
    preserve_suffix: usize,
    restrict_charset: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{PatternsFile, RegistrationOptions, register_with_options};
    use std::io::Read;

    let mut secret = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut secret)?;

    if secret.is_empty() {
        return Err("no secret provided on stdin".into());
    }

    let file_data = read_patterns_file(patterns_path)?;
    let mut pf = PatternsFile::deserialize(&file_data)?;

    let opts = RegistrationOptions {
        preserve_prefix,
        preserve_suffix,
        restrict_charset,
    };
    let pattern = register_with_options(&secret, &opts)?;
    pf.add_tier2_pattern(&pattern, Some(label.to_string()))?;

    let data = pf.serialize()?;
    write_patterns_file(patterns_path, &data, false)?;

    let variable_len = secret.len() - preserve_prefix - preserve_suffix;
    eprintln!(
        "registered Tier 2 secret: {} (variable portion: {} bytes)",
        label, variable_len
    );

    Ok(())
}

fn run_define(
    patterns_path: &Path,
    identifier: &str,
    segment_specs: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::PatternsFile;
    use rand::RngCore;

    let seg_defs: Vec<its_classified::segment::SegmentDef> = segment_specs
        .iter()
        .enumerate()
        .map(|(i, spec)| parse_segment_spec(spec, i))
        .collect::<Result<_, _>>()?;

    let file_data = read_patterns_file(patterns_path)?;
    let mut pf = PatternsFile::deserialize(&file_data)
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    pf.add_tier1_entry(identifier.to_string(), seg_defs, salt)?;

    let data = pf.serialize()?;
    write_patterns_file(patterns_path, &data, false)?;

    let seg_count = segment_specs.len();
    eprintln!(
        "defined Tier 1 pattern: {} ({} segments)",
        identifier, seg_count
    );

    Ok(())
}

fn parse_segment_spec(
    spec: &str,
    index: usize,
) -> Result<its_classified::segment::SegmentDef, String> {
    use its_classified::segment::SegmentDef;

    let (seg_type, rest) = spec.split_once(':').ok_or_else(|| {
        format!(
            "invalid segment spec \"{}\"; expected \"literal:<value>\" or \"variable:<charset>:<min>:<max>\"",
            spec
        )
    })?;

    match seg_type {
        "literal" => Ok(SegmentDef::Literal {
            value: rest.to_string(),
        }),
        "variable" => {
            let parts: Vec<&str> = rest.splitn(3, ':').collect();
            if parts.len() != 3 {
                return Err(format!(
                    "invalid segment spec \"{}\"; expected \"variable:<charset>:<min>:<max>\"",
                    spec
                ));
            }
            let charset = parts[0].to_string();
            let min: usize = parts[1]
                .parse()
                .map_err(|_| format!("segment {}: min is not a valid number", index))?;
            let max: usize = parts[2]
                .parse()
                .map_err(|_| format!("segment {}: max is not a valid number", index))?;
            Ok(SegmentDef::Variable { charset, min, max })
        }
        _ => Err(format!(
            "invalid segment spec \"{}\"; expected \"literal:<value>\" or \"variable:<charset>:<min>:<max>\"",
            spec
        )),
    }
}

fn run_list(patterns_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::PatternsFile;

    let file_data = read_patterns_file(patterns_path)?;
    let pf = PatternsFile::deserialize(&file_data)
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    println!("Tier 1 patterns:");
    if pf.tier1.is_empty() {
        println!("  (none)");
    } else {
        let max_id_len = pf
            .tier1
            .iter()
            .map(|e| e.identifier.len())
            .max()
            .unwrap_or(0);
        let col_width = max_id_len.clamp(10, 40);
        for entry in &pf.tier1 {
            let desc = format_tier1_segments(entry);
            println!("  {:width$}  {}", entry.identifier, desc, width = col_width);
        }
    }

    println!();
    println!("Tier 2 secrets:");
    if pf.tier2.is_empty() {
        println!("  (none)");
    } else {
        for entry in &pf.tier2 {
            let label_str = entry.label.as_deref().unwrap_or("(unlabeled)");
            let charset_desc = format_charset_summary(&entry.charset);
            println!(
                "  {}  length={}  charset={}",
                label_str, entry.exact_length, charset_desc
            );
        }
    }

    Ok(())
}

fn format_tier1_segments(entry: &its_classified::Tier1Entry) -> String {
    match &entry.segments {
        Some(defs) => defs
            .iter()
            .map(|d| match d {
                its_classified::segment::SegmentDef::Literal { value } => {
                    format!("\"{}\"", value)
                }
                its_classified::segment::SegmentDef::Variable { charset, min, max } => {
                    if min == max {
                        format!("<{} {}>", min, charset)
                    } else {
                        format!("<{}-{} {}>", min, max, charset)
                    }
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
        None => "(built-in, segments not in file)".to_string(),
    }
}

fn format_charset_summary(charset: &Option<Vec<u8>>) -> String {
    match charset {
        None => "wide".to_string(),
        Some(cs) => format!("custom ({} chars)", cs.len()),
    }
}

fn run_inspect(
    patterns_path: &Path,
    identifier: Option<&str>,
    label: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::PatternsFile;

    let file_data = read_patterns_file(patterns_path)?;
    let pf = PatternsFile::deserialize(&file_data)
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    if let Some(id) = identifier {
        let entry = pf
            .tier1
            .iter()
            .find(|e| e.identifier == id)
            .ok_or_else(|| format!("no Tier 1 pattern with identifier \"{}\"", id))?;

        let is_builtin = its_classified::PatternsFile::is_builtin_identifier(id);
        let type_str = if is_builtin {
            "built-in"
        } else {
            "user-defined"
        };
        let salt_fingerprint = hex_encode(&entry.salt[..4]);

        println!("Tier 1 pattern: {}", id);
        println!("  Type: {}", type_str);
        println!("  Salt: {}...", &*salt_fingerprint);
        println!("  Segments:");

        match &entry.segments {
            Some(defs) => {
                for (i, d) in defs.iter().enumerate() {
                    match d {
                        its_classified::segment::SegmentDef::Literal { value } => {
                            println!("    {}. literal \"{}\"", i + 1, value);
                        }
                        its_classified::segment::SegmentDef::Variable { charset, min, max } => {
                            println!(
                                "    {}. variable charset={} min={} max={}",
                                i + 1,
                                charset,
                                min,
                                max
                            );
                        }
                    }
                }
            }
            None => {
                println!("    (compiled-in; not stored in file)");
            }
        }
    } else if let Some(lbl) = label {
        let entry = pf
            .tier2
            .iter()
            .find(|e| e.label.as_deref() == Some(lbl))
            .ok_or_else(|| format!("no Tier 2 secret with label \"{}\"", lbl))?;

        let variable = entry.exact_length - entry.preserve_prefix - entry.preserve_suffix;
        let charset_desc = format_charset_summary(&entry.charset);
        let salt_fingerprint = hex_encode(&entry.hmac_salt[..4]);

        println!("Tier 2 secret: {}", lbl);
        println!("  Length: {} bytes", entry.exact_length);
        println!("  Preserve prefix: {} bytes", entry.preserve_prefix);
        println!("  Preserve suffix: {} bytes", entry.preserve_suffix);
        println!("  Variable portion: {} bytes", variable);
        println!("  Charset: {}", charset_desc);
        println!("  Salt: {}...", &*salt_fingerprint);
    } else {
        unreachable!("clap requires --identifier or --label")
    }

    Ok(())
}

fn run_remove(
    patterns_path: &Path,
    identifier: Option<&str>,
    label: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::PatternsFile;

    let file_data = read_patterns_file(patterns_path)?;
    let mut pf = PatternsFile::deserialize(&file_data)
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    if let Some(id) = identifier {
        let pos = pf
            .tier1
            .iter()
            .position(|e| e.identifier == id)
            .ok_or_else(|| {
                format!(
                    "no Tier 1 pattern with identifier \"{}\" in {}",
                    id,
                    patterns_path.display()
                )
            })?;

        if PatternsFile::is_builtin_identifier(id) {
            eprintln!(
                "warning: removing built-in Tier 1 pattern \"{}\"; scrub will no longer detect this secret class",
                id
            );
        }

        pf.tier1.remove(pos);

        let data = pf.serialize()?;
        write_patterns_file(patterns_path, &data, false)?;

        eprintln!("removed Tier 1 pattern: {}", id);
    } else if let Some(lbl) = label {
        let pos = pf
            .tier2
            .iter()
            .position(|e| e.label.as_deref() == Some(lbl))
            .ok_or_else(|| {
                format!(
                    "no Tier 2 secret with label \"{}\" in {}",
                    lbl,
                    patterns_path.display()
                )
            })?;

        pf.tier2.remove(pos);

        let data = pf.serialize()?;
        write_patterns_file(patterns_path, &data, false)?;

        eprintln!("removed Tier 2 secret: {}", lbl);
    } else {
        unreachable!("clap requires --identifier or --label")
    }

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

fn hex_encode(bytes: &[u8]) -> zeroize::Zeroizing<String> {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).expect("writing to String is infallible");
    }
    zeroize::Zeroizing::new(s)
}

fn run_unscrub(entries_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use its_classified::{
        types::{Entry, SessionKey},
        unscrub,
    };
    use std::io;

    // INV-20: session key ONLY via ITS_CLASSIFIED_KEY env var
    let key_hex = zeroize::Zeroizing::new(
        std::env::var("ITS_CLASSIFIED_KEY")
            .map_err(|_| "ITS_CLASSIFIED_KEY environment variable not set")?,
    );
    let key_bytes: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(
        hex_decode(&key_hex).map_err(|_| "ITS_CLASSIFIED_KEY is not valid hex")?,
    );
    let key_array = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(key_bytes.as_slice())
            .map_err(|_| "ITS_CLASSIFIED_KEY must be 64 hex characters (32 bytes)")?,
    );
    let session_key = SessionKey::from_bytes(*key_array);

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
            label,
            preserve_prefix,
            preserve_suffix,
            restrict_charset,
        } => run_register(
            &patterns,
            &label,
            preserve_prefix,
            preserve_suffix,
            restrict_charset,
        ),
        Commands::Define {
            patterns,
            identifier,
            segment,
        } => run_define(&patterns, &identifier, &segment),
        Commands::List { patterns } => run_list(&patterns),
        Commands::Inspect {
            patterns,
            identifier,
            label,
        } => run_inspect(&patterns, identifier.as_deref(), label.as_deref()),
        Commands::Remove {
            patterns,
            identifier,
            label,
        } => run_remove(&patterns, identifier.as_deref(), label.as_deref()),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
