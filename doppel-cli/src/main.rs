use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "doppel",
    about = "Intercept secrets in payloads, replace with fakes, restore from responses",
    long_about = "Intercept secrets in payloads, replace with fakes, restore from responses.\n\nWorkflow:\n  1. doppel init             - create a patterns file (one-time setup)\n  2. doppel register/define  - add secrets to detect\n  3. doppel swap             - replace secrets with fakes; emit swapped payload + entries + key file\n  4. forward swapped payload to the external service\n  5. doppel restore          - pipe the response through to recover originals\n\nThe patterns file is stable across requests. Entries and session key are per-request."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Replace detected secrets with fakes; write swapped payload to stdout.
    ///
    /// Reads the payload from stdin. Writes the swapped payload to stdout.
    /// Also writes an entries file (not sensitive) and a session key file (sensitive,
    /// mode 0600). Both are required by `doppel restore` to reverse the substitution.
    Swap {
        /// Patterns file (created by `init`).
        #[arg(long)]
        patterns: PathBuf,
        /// Output: entries file (ciphertext; pass to `restore` via --entries).
        ///
        /// Not sensitive; safe to store alongside the swapped payload.
        /// Pass to `doppel restore --entries` to reverse the substitution.
        #[arg(long)]
        entries: PathBuf,
        /// Output: session key file (sensitive, mode 0600; export as DOPPEL_KEY for restore).
        ///
        /// Sensitive - created with mode 0600. Export its hex contents as DOPPEL_KEY
        /// before running `doppel restore`.
        #[arg(long = "key-out")]
        key_out: PathBuf,
    },
    /// Restore fakes in a response stream back to their original secrets.
    ///
    /// Reads from stdin; writes restored output to stdout. Streams output -
    /// does not wait for stdin EOF before writing.
    /// Session key: export DOPPEL_KEY with the hex string from swap's key file.
    Restore {
        /// Entries file produced by `doppel swap`.
        #[arg(long)]
        entries: PathBuf,
        // NO --key flag - INV-20: key via DOPPEL_KEY env var only
    },
    /// Create a patterns file with all built-in structural pattern definitions.
    ///
    /// The patterns file configures secret detection and fake generation for `swap`.
    /// Built-in patterns cover common API key formats (Anthropic, OpenAI, AWS, GitHub, GCP).
    /// Use `register` or `define` to add more.
    Init {
        /// Path to create the patterns file.
        #[arg(long)]
        patterns: PathBuf,
        /// Overwrite if file exists.
        ///
        /// WARNING: regenerates all salts - previously produced fakes become invalid.
        #[arg(long)]
        force: bool,
    },
    /// Register a secret (read from stdin) into an existing patterns file.
    ///
    /// Matched by exact value (HMAC-verified). Use when the secret has no structural
    /// pattern, or for guaranteed detection of a specific known value.
    Register {
        /// Path to the patterns file to update.
        #[arg(long)]
        patterns: PathBuf,
        /// Unique identifier for this pattern entry.
        #[arg(long, short = 'i', required_unless_present = "group")]
        identifier: Option<String>,
        /// Add this secret to an existing group pattern (its identifier).
        #[arg(long, short = 'g', conflicts_with = "identifier")]
        group: Option<String>,
        /// Number of leading secret bytes stored as the detection anchor. Default: 3.
        #[arg(long, short = 'a', default_value_t = 3)]
        anchor_len: usize,
        /// Number of trailing secret bytes stored as secondary anchor. Default: 0.
        #[arg(long, short = 't', default_value_t = 0)]
        tail_anchor_len: usize,
        /// Generate fake bytes from the secret's own charset only.
        #[arg(long)]
        restrict_charset: bool,
        /// Trailing run guard threshold in bytes (default: none — no guard).
        ///
        /// When set, the produced Pattern declares a trailing run guard: a
        /// winning match followed by at least this many consecutive
        /// guard-charset bytes is suppressed as a likely slice of an encoded
        /// blob. The guard charset is the Pattern's single `variable` segment
        /// charset. Must be positive; zero is rejected with a clear error.
        #[arg(long)]
        trailing_run_guard: Option<usize>,
        /// Suppress entropy hard-fail (83-bit threshold); warning is still emitted.
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Add a user-defined structural pattern to the patterns file.
    #[command(
        long_about = "Add a user-defined structural pattern to the patterns file.\n\nStructural patterns match secrets by format, not exact value. Supply --segment for each segment in order.\n\nliteral:<value>  -  exact fixed string\n\nvariable:<charset>:<min>:<max>  -  variable-length random segment\n\nCharsets: alphanumeric, uppercase_alphanumeric, digits, hex_lower, url_safe_base64, wide\n\nExample: --segment literal:sk- --segment variable:alphanumeric:48:48"
    )]
    Define {
        /// Path to the patterns file to update.
        #[arg(long)]
        patterns: PathBuf,
        /// Unique identifier for this pattern (e.g. MY_API_KEY).
        #[arg(long)]
        identifier: String,
        /// Segment: "literal:<value>" or "variable:<charset>:<min>:<max>"; repeat in order.
        #[arg(
            long,
            required = true,
            num_args = 1,
            long_help = "Repeat for each segment in order.\n\nliteral:<value>  -  exact fixed string\n\nvariable:<charset>:<min>:<max>  -  variable-length random segment\n\nCharsets: alphanumeric, uppercase_alphanumeric, digits, hex_lower, url_safe_base64, wide\n\nExample: --segment literal:sk- --segment variable:alphanumeric:48:48"
        )]
        segment: Vec<String>,
    },
    /// List all structural patterns and registered secrets in a patterns file.
    List {
        /// Path to the patterns file.
        #[arg(long)]
        patterns: PathBuf,
    },
    /// Show details for a pattern entry.
    Inspect {
        /// Path to the patterns file.
        #[arg(long)]
        patterns: PathBuf,
        /// Identifier of the pattern to inspect.
        #[arg(long, short = 'i', required = true)]
        identifier: String,
    },
    /// Remove a pattern entry from a patterns file.
    Remove {
        /// Path to the patterns file.
        #[arg(long)]
        patterns: PathBuf,
        /// Identifier of the pattern to remove.
        #[arg(long, short = 'i', required = true)]
        identifier: String,
    },
}

const INIT_COMMENT_BLOCK: &str = r#"# doppel patterns file (version 3)
#
# This file defines detection patterns for `doppel swap`. Edit with care.
#
# Each [[pattern]] entry has:
#   identifier = "unique-name"
#   salt = "64 hex characters"
#   digests = ["64 hex chars", ...]  # optional; empty = family pattern
#   [[pattern.segments]] ...
#
# Segment types:
#   { type = "literal", value = "exact bytes" }
#   { type = "opaque", value = "anchor bytes", charset = "name" }
#   { type = "variable", charset = "name", min = N, max = M }
#
# Valid charset names: alphanumeric, url_safe_base64, uppercase_alphanumeric,
#                      digits, hex_lower, wide
#
# Commands:
#   doppel register --patterns <file> --identifier <id> --anchor-len 3 < secret.txt
#   doppel register --patterns <file> --group <id> < another_secret.txt
#   doppel define --patterns <file> --identifier <id> --segment 'literal:prefix_' \
#                 --segment 'variable:alphanumeric:20:20'
#   doppel list --patterns patterns.toml
#   doppel remove --identifier <id> --patterns patterns.toml
#
"#;

fn read_patterns_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(path).map_err(|e| -> Box<dyn std::error::Error> {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "patterns file not found: {}\n  tip: create it with: doppel init --patterns {}",
                path.display(),
                path.display()
            )
            .into()
        } else {
            format!("failed to read patterns file: {}", e).into()
        }
    })
}

fn run_swap(
    patterns_path: &Path,
    entries_path: &Path,
    key_out_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use doppel::{SecretsFile, swap, types::Entry};
    use std::io::{self, Read, Write};

    let file_data = read_patterns_file(patterns_path)?;

    let pf = SecretsFile::deserialize(&file_data)
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    let patterns = pf.to_patterns().map_err(|e| {
        format!(
            "failed to load patterns from {}: {}",
            patterns_path.display(),
            e
        )
    })?;

    let mut payload = Vec::new();
    io::stdin().read_to_end(&mut payload)?;

    let result = swap(&payload, &patterns)?;

    // Serialize in memory first; fail before any output if key file already exists
    let entries_json = Entry::serialize_entries(&result.entries)?;
    write_key_file(key_out_path, result.session_key.as_bytes())?;

    std::fs::write(entries_path, &entries_json)?;
    io::stdout().write_all(&result.payload)?;

    Ok(())
}

fn run_init(patterns_path: &Path, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use doppel::SecretsFile;

    let mut pf = SecretsFile::new();
    pf.generate_missing_structural_salts_with_segments();
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

    let count = pf.pattern.len();
    eprintln!(
        "created patterns file: {} ({} patterns)",
        patterns_path.display(),
        count
    );

    Ok(())
}

// Mirrors the CLI's `register` option surface 1:1; splitting it into a config
// struct would add indirection with no behavioral benefit for a single call site.
#[allow(clippy::too_many_arguments)]
fn run_register(
    patterns_path: &Path,
    identifier: Option<&str>,
    group: Option<&str>,
    anchor_len: usize,
    tail_anchor_len: usize,
    restrict_charset: bool,
    trailing_run_guard: Option<usize>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use doppel::{SecretOptions, SecretsFile, register_with_options};
    use std::io::Read;

    let mut secret = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut secret)?;

    if secret.is_empty() {
        return Err("no secret provided on stdin".into());
    }

    let file_content = std::fs::read_to_string(patterns_path).map_err(|_| {
        format!(
            "patterns file not found: {}\n  tip: create it with: doppel init --patterns {}",
            patterns_path.display(),
            patterns_path.display()
        )
    })?;

    let mut doc: toml_edit::DocumentMut = file_content
        .parse()
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    let mut pf = SecretsFile::deserialize(file_content.as_bytes())
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    if let Some(group_id) = group {
        pf.add_secret_to_group(group_id, &secret)?;

        // Get the hex of the newly appended digest
        let new_digest_hex = {
            let entry = pf
                .pattern
                .iter()
                .find(|e| e.identifier == group_id)
                .expect("entry just updated");
            let digest = entry.digests.last().expect("just pushed");
            hex_encode(digest)
        };

        // Surgically append only the new digest to the existing entry's digests array,
        // preserving inline comments, entry position, and all other fields (INV-37).
        // Each ok_or propagates as an error rather than silently no-oping.
        let aot = doc["pattern"]
            .as_array_of_tables_mut()
            .ok_or("TOML structure error: 'pattern' is not an array-of-tables")?;
        let table = aot
            .iter_mut()
            .find(|t| t["identifier"].as_str() == Some(group_id))
            .ok_or_else(|| format!("TOML structure error: '{}' not found in doc", group_id))?;
        let arr = table["digests"]
            .as_array_mut()
            .ok_or("TOML structure error: 'digests' is not an inline array")?;
        arr.push(new_digest_hex.as_str());

        let new_content = doc.to_string();
        write_patterns_file(patterns_path, new_content.as_bytes(), false)?;
        eprintln!("added digest to group: {}", group_id);
    } else {
        let id = identifier.expect("clap: --identifier required when --group absent");

        let opts = SecretOptions {
            anchor_len,
            tail_anchor_len,
            restrict_charset,
            trailing_run_guard,
            trailing_run_guard_charset: None,
            force,
        };
        let pattern = register_with_options(&secret, &opts)?;
        pf.add_secret_pattern(id.to_string(), &pattern)?;

        let new_entry = pf.pattern.last().expect("entry just added");
        let item = toml_edit::ser::to_document(new_entry)
            .map_err(|e| format!("failed to serialize entry: {}", e))?
            .into_item();
        let table = item
            .into_table()
            .map_err(|_| "serialized entry was not a TOML table")?;

        if doc
            .get("pattern")
            .map(|i| i.is_array_of_tables())
            .unwrap_or(false)
        {
            doc["pattern"].as_array_of_tables_mut().unwrap().push(table);
        } else {
            doc.remove("pattern");
            let mut aot = toml_edit::ArrayOfTables::new();
            aot.push(table);
            doc.insert("pattern", toml_edit::Item::ArrayOfTables(aot));
        }

        let new_content = doc.to_string();
        write_patterns_file(patterns_path, new_content.as_bytes(), false)?;

        let middle_len = secret
            .len()
            .saturating_sub(anchor_len)
            .saturating_sub(tail_anchor_len.min(secret.len().saturating_sub(anchor_len)));
        eprintln!(
            "registered secret: {} (variable portion: {} bytes)",
            id, middle_len
        );
    }

    Ok(())
}

fn run_define(
    patterns_path: &Path,
    identifier: &str,
    segment_specs: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use doppel::SecretsFile;
    use rand::RngCore;

    let seg_defs: Vec<doppel::segment::SegmentDef> = segment_specs
        .iter()
        .enumerate()
        .map(|(i, spec)| parse_segment_spec(spec, i))
        .collect::<Result<_, _>>()?;

    let file_content = std::fs::read_to_string(patterns_path).map_err(|_| {
        format!(
            "patterns file not found: {}\n  tip: create it with: doppel init --patterns {}",
            patterns_path.display(),
            patterns_path.display()
        )
    })?;

    let mut doc: toml_edit::DocumentMut = file_content
        .parse()
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    let mut pf = SecretsFile::deserialize(file_content.as_bytes())
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    // Capture first-segment length before ownership transfer for the advisory warning.
    let first_seg_anchor_len = seg_defs
        .first()
        .map(|s| match s {
            doppel::segment::SegmentDef::Literal { value } => value.len(),
            doppel::segment::SegmentDef::Opaque { value, .. } => value.len(),
            _ => 0,
        })
        .unwrap_or(0);

    pf.add_structural_entry(identifier.to_string(), seg_defs, salt)?;

    // Warn when the first-segment anchor is short but above the hard-fail threshold.
    if (2..4).contains(&first_seg_anchor_len) {
        log::warn!(
            "doppel: first segment is {} byte(s); patterns with fewer than 4 anchor bytes may generate many false Aho-Corasick candidates in high-throughput contexts",
            first_seg_anchor_len
        );
    }

    let new_entry = pf.pattern.last().expect("entry just added");
    let item = toml_edit::ser::to_document(new_entry)
        .map_err(|e| format!("failed to serialize entry: {}", e))?
        .into_item();
    let table = item
        .into_table()
        .map_err(|_| "serialized entry was not a TOML table")?;

    if doc
        .get("pattern")
        .map(|i| i.is_array_of_tables())
        .unwrap_or(false)
    {
        doc["pattern"].as_array_of_tables_mut().unwrap().push(table);
    } else {
        doc.remove("pattern");
        let mut aot = toml_edit::ArrayOfTables::new();
        aot.push(table);
        doc.insert("pattern", toml_edit::Item::ArrayOfTables(aot));
    }

    let new_content = doc.to_string();
    write_patterns_file(patterns_path, new_content.as_bytes(), false)?;

    let seg_count = segment_specs.len();
    eprintln!(
        "defined Structural pattern: {} ({} segments)",
        identifier, seg_count
    );

    Ok(())
}

fn parse_segment_spec(spec: &str, index: usize) -> Result<doppel::segment::SegmentDef, String> {
    use doppel::segment::SegmentDef;

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
        "opaque" => {
            // Format: opaque:<value> or opaque:<value>:<charset>
            let mut parts = rest.splitn(2, ':');
            let value = parts.next().unwrap_or("").to_string();
            let charset = parts.next().map(|s| s.to_string());
            Ok(SegmentDef::Opaque { value, charset })
        }
        _ => Err(format!(
            "invalid segment spec \"{}\"; expected \"literal:<value>\", \"opaque:<value>[:<charset>]\", or \"variable:<charset>:<min>:<max>\"",
            spec
        )),
    }
}

fn run_list(patterns_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use doppel::SecretsFile;

    let file_data = read_patterns_file(patterns_path)?;
    let pf = SecretsFile::deserialize(&file_data)
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    println!("Patterns:");
    if pf.pattern.is_empty() {
        println!("  (none)");
    } else {
        let max_id_len = pf
            .pattern
            .iter()
            .map(|e| e.identifier.len())
            .max()
            .unwrap_or(0);
        let col_width = max_id_len.clamp(10, 40);
        for entry in &pf.pattern {
            let kind = if entry.digests.is_empty() {
                "family"
            } else {
                "instance"
            };
            let desc = format_pattern_segments(entry);
            println!(
                "  {:width$}  [{}]  {}  ({} digests)",
                entry.identifier,
                kind,
                desc,
                entry.digests.len(),
                width = col_width
            );
        }
    }

    Ok(())
}

fn format_pattern_segments(entry: &doppel::PatternEntry) -> String {
    entry
        .segments
        .iter()
        .map(|d| match d {
            doppel::segment::SegmentDef::Literal { value } => {
                format!("\"{}\"", value)
            }
            doppel::segment::SegmentDef::Variable { charset, min, max } => {
                if min == max {
                    format!("<{} {}>", min, charset)
                } else {
                    format!("<{}-{} {}>", min, max, charset)
                }
            }
            doppel::segment::SegmentDef::Opaque { value, charset } => {
                let cs = charset.as_deref().unwrap_or("alphanumeric");
                format!("[opaque:{} {}]", cs, value)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn charset_size(name: &str) -> usize {
    match name {
        "alphanumeric" => 62,
        "url_safe_base64" => 64,
        "uppercase_alphanumeric" => 36,
        "digits" => 10,
        "hex_lower" => 16,
        "wide" => 92,
        _ => 0,
    }
}

fn entropy_estimate(min: usize, max: usize, charset: &str) -> String {
    let size = charset_size(charset);
    if size <= 1 {
        return "0.0 bits".to_string();
    }
    let bits_per_byte = (size as f64).log2();
    let lo = min as f64 * bits_per_byte;
    if min == max {
        format!("{:.1} bits", lo)
    } else {
        let hi = max as f64 * bits_per_byte;
        format!("{:.1}-{:.1} bits", lo, hi)
    }
}

fn run_inspect(patterns_path: &Path, identifier: &str) -> Result<(), Box<dyn std::error::Error>> {
    use doppel::SecretsFile;

    let file_data = read_patterns_file(patterns_path)?;
    let pf = SecretsFile::deserialize(&file_data)
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    let entry = pf
        .pattern
        .iter()
        .find(|e| e.identifier == identifier)
        .ok_or_else(|| format!("no pattern with identifier \"{}\"", identifier))?;

    let is_builtin = doppel::SecretsFile::is_builtin_identifier(identifier);
    let type_str = if is_builtin {
        "built-in"
    } else {
        "user-defined"
    };
    let salt_fingerprint = hex_encode(&entry.salt[..4]);

    let kind = if entry.digests.is_empty() {
        "family"
    } else {
        "instance"
    };
    println!("Pattern: {}", identifier);
    println!("  Kind: {}", kind);
    println!("  Type: {}", type_str);
    println!("  Digests: {}", entry.digests.len());
    println!("  Salt: {}...", &*salt_fingerprint);
    println!("  Segments:");

    for (i, d) in entry.segments.iter().enumerate() {
        match d {
            doppel::segment::SegmentDef::Literal { value } => {
                println!("    {}. literal \"{}\"", i + 1, value);
            }
            doppel::segment::SegmentDef::Variable { charset, min, max } => {
                let entropy = entropy_estimate(*min, *max, charset);
                println!(
                    "    {}. variable charset={} min={} max={} (~{})",
                    i + 1,
                    charset,
                    min,
                    max,
                    entropy
                );
            }
            doppel::segment::SegmentDef::Opaque { value, charset } => {
                println!(
                    "    {}. opaque value={} charset={}",
                    i + 1,
                    value,
                    charset.as_deref().unwrap_or("alphanumeric")
                );
            }
        }
    }

    Ok(())
}

fn run_remove(patterns_path: &Path, identifier: &str) -> Result<(), Box<dyn std::error::Error>> {
    use doppel::SecretsFile;

    let file_content = std::fs::read_to_string(patterns_path).map_err(|_| {
        format!(
            "patterns file not found: {}\n  tip: create it with: doppel init --patterns {}",
            patterns_path.display(),
            patterns_path.display()
        )
    })?;

    let mut doc: toml_edit::DocumentMut = file_content
        .parse()
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    let pf = SecretsFile::deserialize(file_content.as_bytes())
        .map_err(|e| format!("invalid patterns file: {}: {}", patterns_path.display(), e))?;

    pf.pattern
        .iter()
        .position(|e| e.identifier == identifier)
        .ok_or_else(|| {
            format!(
                "no pattern with identifier \"{}\" in {}",
                identifier,
                patterns_path.display()
            )
        })?;

    if SecretsFile::is_builtin_identifier(identifier) {
        eprintln!(
            "warning: removing built-in pattern \"{}\"; swap will no longer detect this secret class",
            identifier
        );
    }

    if let Some(aot) = doc["pattern"].as_array_of_tables_mut() {
        let idx = aot
            .iter()
            .position(|t| t["identifier"].as_str() == Some(identifier));
        if let Some(i) = idx {
            aot.remove(i);
        }
    }

    let new_content = doc.to_string();
    write_patterns_file(patterns_path, new_content.as_bytes(), false)?;

    eprintln!("removed pattern: {}", identifier);
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

fn run_restore(entries_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use doppel::{
        restore,
        types::{Entry, SessionKey},
    };
    use std::io;

    // INV-20: session key ONLY via DOPPEL_KEY env var
    let key_hex = zeroize::Zeroizing::new(
        std::env::var("DOPPEL_KEY").map_err(|_| "DOPPEL_KEY environment variable not set")?,
    );
    let key_bytes: zeroize::Zeroizing<Vec<u8>> =
        zeroize::Zeroizing::new(hex_decode(&key_hex).map_err(|_| "DOPPEL_KEY is not valid hex")?);
    let key_array = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(key_bytes.as_slice())
            .map_err(|_| "DOPPEL_KEY must be 64 hex characters (32 bytes)")?,
    );
    let session_key = SessionKey::from_bytes(*key_array);

    let entries_data = std::fs::read(entries_path)?;
    let entries = Entry::deserialize_entries(&entries_data)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    restore(
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
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Warn)
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Swap {
            patterns,
            entries,
            key_out,
        } => run_swap(&patterns, &entries, &key_out),
        Commands::Restore { entries } => run_restore(&entries),
        Commands::Init { patterns, force } => run_init(&patterns, force),
        Commands::Register {
            patterns,
            identifier,
            group,
            anchor_len,
            tail_anchor_len,
            restrict_charset,
            trailing_run_guard,
            force,
        } => run_register(
            &patterns,
            identifier.as_deref(),
            group.as_deref(),
            anchor_len,
            tail_anchor_len,
            restrict_charset,
            trailing_run_guard,
            force,
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
        } => run_inspect(&patterns, &identifier),
        Commands::Remove {
            patterns,
            identifier,
        } => run_remove(&patterns, &identifier),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
