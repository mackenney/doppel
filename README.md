# doppel

Scrubs secrets from arbitrary byte payloads before they leave your machine,
then restores them transparently in the response — including SSE streams.

**Status:** implemented. See [SPEC.md](SPEC.md) for the behavioral contract.

## How it works

```
swap(payload, patterns)  →  (swapped_payload, entries, session_key)
restore(response_stream, entries, session_key)  →  restored_stream
```

You supply the patterns. `swap` applies exactly the patterns you pass — nothing
more. Secrets matching those patterns are replaced with structurally-equivalent
fakes before the payload leaves. `restore` reverses the substitution in the
response stream using the encrypted entries and the session key.

## Patterns

**You decide what gets swapped.** A pattern describes how to detect and replace
one secret or one class of secrets. There are two kinds:

### Tier 1 — structural classes

A Tier 1 pattern describes the *shape* of a secret class: an ordered sequence of
**Literal** segments (fixed byte sequences) and **Variable** segments (a character
set with a length range). Detection fires on any payload byte that matches that
shape; no prior knowledge of the actual secret value is required.

The library ships built-in Tier 1 definitions for common providers (Anthropic,
OpenAI, AWS, GitHub, GCP). These are available as a starting set — you opt into
them; they are not applied automatically.

### Tier 2 — specific known secrets

A Tier 2 pattern covers a secret that has no structural class: you know the
actual value and want it swapped wherever it appears. You register the full
secret bytes; the library derives a detection fingerprint and generates a fake
at registration time. The original value is never stored.

```rust
// Simple registration (default options)
let pat = register(b"my-super-secret-api-token")?;

// With options: preserve a non-secret prefix, restrict fake charset
let pat = register_with_options(b"MY_ORG_secretpart_END", &SecretOptions {
    preserve_prefix: 7,  // "MY_ORG_" reproduced verbatim in every fake
    preserve_suffix: 4,  // "_END" reproduced verbatim in every fake
    restrict_charset: false,
})?;
```

`SecretOptions` lets you declare a non-secret prefix/suffix (preserved
verbatim in the fake) and restrict the fake's character set to match the
original's. `register` is shorthand for `register_with_options` with all defaults.

### Salt — stable fakes across runs

Every pattern carries a **salt**: a 32-byte random value generated once when the
pattern is first registered. The salt is the stability guarantee:

```
same secret + same pattern + same salt → same fake, every run
```

Without a fixed salt, each process restart generates a new one and the same
secret gets a different fake each time — correct within a single cycle but
inconsistent across runs. For the CLI patterns file the salt is written into the
file on first use and stays fixed forever; you own it along with the rest of the
pattern definition.

### Patterns file (CLI)

The CLI reads patterns from a TOML file (version 2). You create it with `init`
and extend it with `register` and `define`. Each entry embeds its salt, so fakes
are stable across process restarts.

**Create a new patterns file:**

```sh
doppel init --patterns secrets.toml
```

This writes a self-describing TOML file with all built-in Tier 1 definitions and
freshly generated salts. The Tier 2 list starts empty.

**Patterns file structure:**

```toml
version = 2
tier2 = []

[[tier1]]
identifier = "anthropic"
salt = "47abb6fb..."   # 64 hex chars (32 bytes)

[[tier1.segments]]
type = "literal"
value = "sk-ant-api03-"

[[tier1.segments]]
type = "variable"
charset = "url_safe_base64"
min = 93
max = 93

[[tier1.segments]]
type = "literal"
value = "AA"

# ... more [[tier1]] entries for other built-in classes ...

[[tier2]]
label = "my-api-key"
start_fragment = "6d792d..."    # hex; detection anchor (first bytes of secret)
end_fragment   = "6c75652d..."  # hex; detection anchor (last bytes of secret)
exact_length   = 36
hmac_salt      = "ff3c005b..."  # hex; unique per registration
hmac_digest    = "8a5843ef..."  # hex; HMAC confirmation token
preserve_prefix = 3
preserve_suffix = 0
# charset omitted → wide default ([A-Za-z0-9!@#$%^&*\-_+.~|])
```

Valid charset names for Tier 1 segments: `alphanumeric`, `url_safe_base64`,
`uppercase_alphanumeric`, `digits`, `hex_lower`.

The file MUST be treated with the same sensitivity as the secrets it detects — it
contains detection fragments. On Unix systems, all write operations (`init`,
`register`, `define`) create or update the file with mode 0600.

## CLI reference

### `init` — create a patterns file

```sh
doppel init --patterns secrets.toml [--force]
```

Creates a new TOML patterns file with all built-in Tier 1 definitions and freshly
generated salts. Fails if the file already exists; use `--force` to overwrite
(warning: regenerates all salts — existing fakes become invalid).

### `swap` — swap a payload

```sh
doppel swap \
  --patterns secrets.toml \
  --entries  entries.json \
  --key-out  session.key \
  < request_body.json > swapped_body.json
```

Reads the complete payload from stdin, writes the swapped payload to stdout,
writes the entries (ciphertext; not sensitive on its own) to `--entries`, and
writes the session key (sensitive; mode 0600) to `--key-out`.

### `restore` — restore a response stream

```sh
export DOPPEL_KEY=$(cat session.key)
doppel restore --entries entries.json < response_stream > restored.txt
```

Reads the response stream from stdin incrementally and writes restored output to
stdout as each chunk resolves. The session key is supplied **only** via the
`DOPPEL_KEY` environment variable — no `--key` flag exists (command-line
arguments are visible in process listings and shell history).

### `register` — register a Tier 2 secret

```sh
echo -n 'my-secret-value' | doppel register \
  --patterns secrets.toml \
  --label    my-api-key \
  [--preserve-prefix N] \
  [--preserve-suffix M] \
  [--restrict-charset]
```

Reads the secret from stdin (raw bytes, no trimming), appends a new Tier 2 entry
to the patterns file, and writes it back atomically. The secret never appears in
command-line arguments. `--label` is required and must be unique within the file.

### `define` — add a user-defined Tier 1 pattern

```sh
doppel define \
  --patterns   secrets.toml \
  --identifier MY_PATTERN \
  --segment    literal:MY_PREFIX_ \
  --segment    variable:alphanumeric:32:32
```

Adds a structural Tier 1 pattern. `--segment` is repeatable; pass it once per
segment in order. Segment specs:
- `literal:<value>` — fixed byte sequence
- `variable:<charset>:<min>:<max>` — variable-length field from named charset

Valid charset names: `alphanumeric`, `url_safe_base64`, `uppercase_alphanumeric`,
`digits`, `hex_lower`.

At least one Variable segment is required. The identifier must be unique in the
file.

### `list` — list all patterns

```sh
doppel list --patterns secrets.toml
```

Prints a human-readable summary: Tier 1 entries with identifier and segment
description; Tier 2 entries with label, exact length, and charset summary. Does
not modify the file.

### `inspect` — show detail for one pattern

```sh
doppel inspect --patterns secrets.toml --identifier anthropic
doppel inspect --patterns secrets.toml --label my-api-key
```

Exactly one of `--identifier` (Tier 1) or `--label` (Tier 2) is required.
Prints full detail for the matched entry: all segments and salt fingerprint (first
8 hex chars) for Tier 1; length, charset, and derivation parameters for Tier 2.
Does not modify the file.

### `remove` — remove a pattern

```sh
doppel remove --patterns secrets.toml --identifier anthropic
doppel remove --patterns secrets.toml --label my-api-key
```

Exactly one of `--identifier` (Tier 1) or `--label` (Tier 2) is required.
Removes the specified entry and writes the file back atomically. Removing a
built-in Tier 1 identifier emits a warning but succeeds; `swap` will no longer
detect that secret class.

## Streaming

`restore` works over a stream of `Bytes` chunks. It uses suspicion-driven
buffering: chunks are held only while a potential match is in flight, bounded by
the longest secret length across active patterns (typically 100–200 bytes).
