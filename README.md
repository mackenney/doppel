# doppel

Swaps secrets from arbitrary payloads with structurally-equivalent fakes, then
restores the originals transparently in the response.

The name comes from *doppelgänger*: each fake replacing a secret is its structural
twin — same format, different value.

See [SPEC.md](SPEC.md) for the behavioral contract.

## How it works

```
              secrets.toml
     ┌─────────────────────────────┐
     │ [[pattern]] anthropic, …    │
     │ [[pattern]] db-password     │
     └──────────────┬──────────────┘
                 patterns
                    │
               ┌────▼────┐
  payload ───▶ │  swap   │── swapped payload ────▶ External
  sk-ant-REAL  └────┬────┘     sk-ant-FAKE         (eg. LLM)
                    │                                 │
                entries +                             │
               session_key                     response stream
                    │                        (may contain fakes)
 restored      ┌────▼────┐                            │
  payload ◀─── │ restore │◀───────────────────────────┘
  sk-ant-REAL  └─────────┘     sk-ant-FAKE

```

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
one secret or one class of secrets. Every pattern is a `[[pattern]]` entry in the
TOML file; the distinction between detecting by shape vs. detecting by value is made
via the segment definitions:

### Structural patterns

A structural pattern describes the *shape* of a secret class: an ordered sequence of
**Literal** segments (fixed byte sequences), **Variable** segments (a character set
with a length range), and optionally **Opaque** segments (fixed bytes for detection
but re-derived in fake generation). Detection fires on any payload byte that matches
that shape; no prior knowledge of the actual secret value is required.

The library ships built-in structural pattern definitions for 27 providers (Anthropic,
OpenAI, AWS, GitHub, GCP, Stripe, Clerk, and more). These are available as a starting
set — you opt into them; they are not applied automatically.

### Registered secrets

A registered pattern covers a secret that does not conform to any known structural
class: you know the actual value and want it swapped wherever it appears. You register
the full secret bytes; the library derives a detection fingerprint and generates a fake
deterministically from a salt. The original value is never stored.

```rust
// Simple registration (default options: 3-byte detection anchor)
let pat = register(b"my-super-secret-api-token")?;

// With options: longer anchor for lower false-positive rate
let pat = register_with_options(b"my-super-secret-api-token", &SecretOptions {
    anchor_len: 6,           // store 6 leading bytes as the detection anchor
    tail_anchor_len: 0,      // no trailing anchor
    restrict_charset: false, // fake uses wide charset by default
    force: false,            // reject secrets below 83-bit entropy
})?
```

`SecretOptions` controls the detection anchor length (`anchor_len`, default 3),
an optional trailing anchor (`tail_anchor_len`), fake charset restriction, and an
entropy override (`force`). `register` is shorthand for `register_with_options` with
all defaults.

Source: [`doppel/src/secrets.rs`](doppel/src/secrets.rs).

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

### Patterns file

The CLI reads patterns from a TOML file (version 3). You create it with `init`
and extend it with `register` and `define`. Each entry embeds its salt, so fakes
are stable across process restarts.

Library users can load a patterns file programmatically:

```rust
use doppel::{SecretsFile, swap};

let data = std::fs::read("secrets.toml")?;
let sf = SecretsFile::deserialize(&data)?;
let patterns = sf.to_patterns()?;
let result = swap(&payload, &patterns)?;
```


For long-running processes that call `swap` on every incoming request, use
[`Detector`](https://docs.rs/doppel/latest/doppel/struct.Detector.html). The free
`swap` function rebuilds an internal multi-pattern search structure on every call;
`Detector` builds it once at startup and reuses it across all requests, which makes
a measurable difference at hundreds of requests per second.

`Detector` is `Send + Sync`, so you can store it in an `Arc` and share it across
threads or async tasks. The full swap→restore cycle with `Detector`:

```rust
use doppel::{Detector, SecretsFile, restore};
use std::sync::Arc;

// At startup — build once:
let data = std::fs::read("secrets.toml")?;
let patterns = SecretsFile::deserialize(&data)?.to_patterns()?;
let detector = Arc::new(Detector::new(patterns));

// Per request — swap outgoing payload:
let result = detector.swap(&outgoing_payload)?;
// result.payload      — send to external service (secrets replaced with fakes)
// result.entries      — keep locally
// result.session_key  — keep locally

// Per response — restore incoming stream:
let mut restored = Vec::new();
restore(
    &mut response_stream,
    &mut restored,
    &result.entries,
    &result.session_key,
)?;
// restored now contains the original secret bytes
```

**Create a new patterns file:**

```sh
doppel init --patterns secrets.toml
```

This writes a self-describing TOML file with all built-in structural pattern
definitions and freshly generated salts. The registered secrets list starts empty.

**Patterns file structure:**

```toml
version = 3

[[pattern]]
identifier = "anthropic"
salt = "47abb6fb..."   # 64 hex chars (32 bytes); generated by `doppel init`

[[pattern.segments]]
type = "literal"
value = "sk-ant-api03-"

[[pattern.segments]]
type = "variable"
charset = "url_safe_base64"
min = 93
max = 93

[[pattern.segments]]
type = "literal"
value = "AA"

# ... more [[pattern]] entries for other built-in providers ...

# Instance pattern (registered secret — added by `doppel register`):
[[pattern]]
identifier = "my-api-key"
salt = "ff3c005b..."         # 64 hex chars; unique per registration
digests = [
  "8a5843ef...",             # HMAC-SHA256(salt, secret)
]

[[pattern.segments]]
type = "opaque"              # detection anchor: first anchor_len bytes of the secret
value = "my-"

[[pattern.segments]]
type = "variable"
charset = "alphanumeric"
min = 33
max = 33
```

Valid charset names for structural pattern segments: `alphanumeric`, `url_safe_base64`,
`uppercase_alphanumeric`, `digits`, `hex_lower`, `wide`.

(`wide` = 92 printable ASCII bytes: 0x21–0x7E excluding `"` and `\`; used by default for
registered-secret variable segments.)

The file MUST be treated with the same sensitivity as the secrets it detects — it
contains detection fragments. On Unix systems, all write operations (`init`,
`register`, `define`) create or update the file with mode 0600.

## CLI reference

### `init` — create a patterns file

```sh
doppel init --patterns secrets.toml [--force]
```

Creates a new TOML patterns file with all built-in structural pattern definitions
and freshly generated salts. Fails if the file already exists; use `--force` to
overwrite (warning: regenerates all salts — existing fakes become invalid).

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

### `register` — register a secret

```sh
echo -n 'my-secret-value' | doppel register \
  --patterns    secrets.toml \
  --identifier  my-api-key \
  [--anchor-len N] \
  [--tail-anchor-len M] \
  [--restrict-charset] \
  [--force]
```

Reads the secret from stdin (raw bytes, no trimming), appends a new instance-pattern
entry to the patterns file, and writes it back atomically. The secret never appears in
command-line arguments. `--identifier` is required and must be unique within the file.

Alternatively, use `--group <id>` instead of `--identifier` to add this secret as an
additional digest to an existing group pattern (for grouping multiple secrets under one
detection rule).

Source: [`doppel/src/secrets.rs`](doppel/src/secrets.rs) (registration logic) · [`doppel-cli/src/main.rs`](doppel-cli/src/main.rs) (`run_register`).

### `define` — add a user-defined structural pattern

```sh
doppel define \
  --patterns   secrets.toml \
  --identifier MY_PATTERN \
  --segment    literal:MY_PREFIX_ \
  --segment    variable:alphanumeric:32:32
```

Adds a structural pattern. `--segment` is repeatable; pass it once per
segment in order. Segment specs:
- `literal:<value>` — fixed byte sequence
- `variable:<charset>:<min>:<max>` — variable-length field from named charset

Valid charset names: `alphanumeric`, `url_safe_base64`, `uppercase_alphanumeric`,
`digits`, `hex_lower`, `wide`.

At least one Variable segment is required. The identifier must be unique in the
file.

### `list` — list all patterns

```sh
doppel list --patterns secrets.toml
```

Prints a human-readable summary: each `[[pattern]]` entry's identifier, kind (`family` or
`instance`), segment description, and digest count. Does not modify the file.

### `inspect` — show detail for one pattern

```sh
doppel inspect --patterns secrets.toml --identifier anthropic
doppel inspect --patterns secrets.toml --identifier my-api-key
```

`--identifier` is required. Accepts any pattern kind (family or instance).
Prints full detail for the matched entry: all segments, salt fingerprint (first 8 hex
chars), kind, and digest count. Does not modify the file.

### `remove` — remove a pattern

```sh
doppel remove --patterns secrets.toml --identifier anthropic
doppel remove --patterns secrets.toml --identifier my-api-key
```

`--identifier` is required. Removes the specified entry and writes the file back
atomically. Removing a built-in structural pattern identifier emits a warning but
succeeds; `swap` will no longer detect that secret class.

## Streaming

`restore` processes a stream incrementally. It uses suspicion-driven buffering:
chunks are held only while a potential match is in flight, bounded by the longest
secret length across active patterns (typically 100–200 bytes).

### Async streaming (`async` feature)

```toml
[dependencies]
doppel = { version = "0.0.1", features = ["async"] }
```

With the `async` feature, `RestoreStream` wraps entries and session key into a
`futures_core::Stream` adapter. Pass it any `Stream<Item = Result<Bytes, E>>` and
it yields restored `Bytes` chunks as they arrive — no runtime dependency beyond
`futures-core` and `bytes`.

## For the paranoid

Registered secrets are stored as: a 32-byte `salt`, an `opaque` segment holding the
first `anchor_len` bytes of the secret (default 3), a `variable` segment encoding the
remaining byte count, and one or more HMAC-SHA256 digests (`HMAC(salt, secret)`) in the
`digests` array — never as the plaintext value. The source of truth is
[`doppel/src/secrets.rs`](doppel/src/secrets.rs).

You can verify any registered entry against its original secret using only `openssl`,
`python3`, and standard POSIX utilities, and independently reproduce the fake doppel
will generate. See [docs/for-the-paranoid.md](docs/for-the-paranoid.md) for the full
audit script and fake-derivation walkthrough.
