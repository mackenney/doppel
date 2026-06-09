# Step 04 — `README.md` rewrite

**Wave:** 2 (after Wave 0 — steps 01 and 02 — completes)
**Status:** ⬜ pending

## Context

`README.md` (309 lines) still contains large v2-era content: a v2 diagram, a v2 TOML
example block, v2 CLI flags (`--label`, `--preserve-prefix`, `--preserve-suffix`), and
wrong provider counts and charset lists. This step surgically replaces all wrong sections
with v3-accurate content while leaving correct sections unchanged.

## Prerequisites

- Step-01 and step-02 must be ✅ complete (TOML example structure is verified there)
- `cargo clippy` and `cargo nextest run` must pass before starting this step

## Files to read before editing

Read `README.md` in full (`read path="README.md"`) to obtain fresh `LINE#HASH` anchors.
Key regions by line number (verify against current anchors):
- Lines 14–17 (ASCII diagram box)
- Lines 44–58 (Patterns intro + structural patterns)
- Lines 60–83 (registered secrets section + Rust example)
- Line 102 ("version 2")
- Lines 127–162 (TOML example block)
- Lines 163–165 (charset list after TOML block)
- Lines 209–224 (`register` CLI subsection)
- Lines 247–255 (`list` CLI subsection)
- Lines 257–267 (`inspect` CLI subsection)
- Lines 269–279 (`remove` CLI subsection)
- Lines 299–309 (`For the paranoid` section at end)

Also read `doppel-cli/src/main.rs` lines 65–91 (Register subcommand args) to confirm
current CLI flag names before writing the updated CLI reference.

## Implementation tasks

Work through the README from top to bottom. Each task is a targeted replacement.

---

### 1 — ASCII diagram box (lines ~16–17)

**Current:**
```
     │ [[structural]] anthropic, … │
     │ [[registered]]  db-password │
```

**Replace with:**
```
     │ [[pattern]] anthropic, …    │
     │ [[pattern]] db-password     │
```

Keep the box-drawing characters and indentation intact. Only the text inside the box
changes.

---

### 2 — "Two kinds" intro sentence (line ~47)

**Current:**
```markdown
one secret or one class of secrets. There are two kinds:
```

**Replace with:**
```markdown
one secret or one class of secrets. Every pattern is a `[[pattern]]` entry in the
TOML file; the distinction between detecting by shape vs. detecting by value is made
via the segment definitions:
```

---

### 3 — Structural patterns description (lines ~51–54)

**Current:**
```markdown
A structural pattern describes the *shape* of a secret class: an ordered sequence of
**Literal** segments (fixed byte sequences) and **Variable** segments (a character
set with a length range). Detection fires on any payload byte that matches that
shape; no prior knowledge of the actual secret value is required.
```

**Replace with:**
```markdown
A structural pattern describes the *shape* of a secret class: an ordered sequence of
**Literal** segments (fixed byte sequences), **Variable** segments (a character set
with a length range), and optionally **Opaque** segments (fixed bytes for detection
but re-derived in fake generation). Detection fires on any payload byte that matches
that shape; no prior knowledge of the actual secret value is required.
```

---

### 4 — Built-in provider list (line ~57)

**Current:**
```markdown
The library ships built-in structural pattern definitions for common providers (Anthropic,
OpenAI, AWS, GitHub, GCP). These are available as a starting set — you opt into
them; they are not applied automatically.
```

**Replace with:**
```markdown
The library ships built-in structural pattern definitions for 27 providers (Anthropic,
OpenAI, AWS, GitHub, GCP, Stripe, Clerk, and more). These are available as a starting
set — you opt into them; they are not applied automatically.
```

---

### 5 — Registered secrets Rust code example (lines ~67–81)

**Current block** (from the opening ` ```rust ` to the closing ` ``` ` and the following
prose on lines 79–81):
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

Then lines 79–81:
```markdown
`SecretOptions` lets you declare a non-secret prefix/suffix (preserved
verbatim in the fake) and restrict the fake's character set to match the
original's. `register` is shorthand for `register_with_options` with all defaults.
```

**Replace the code block with:**
```rust
// Simple registration (default options: 3-byte detection anchor)
let pat = register(b"my-super-secret-api-token")?;

// With options: longer anchor for lower false-positive rate
let pat = register_with_options(b"my-super-secret-api-token", &SecretOptions {
    anchor_len: 6,          // store 6 leading bytes as the detection anchor
    tail_anchor_len: 0,     // no trailing anchor
    restrict_charset: false, // fake uses wide charset by default
    force: false,           // reject secrets below 83-bit entropy
})?;
```

**Replace the prose (lines 79–81) with:**
```markdown
`SecretOptions` controls the detection anchor length (`anchor_len`, default 3),
an optional trailing anchor (`tail_anchor_len`), fake charset restriction, and an
entropy override (`force`). `register` is shorthand for `register_with_options` with
all defaults.
```

---

### 6 — "Version 2" → "Version 3" (line ~102)

**Current:**
```markdown
The CLI reads patterns from a TOML file (version 2). You create it with `init`
```

**Replace with:**
```markdown
The CLI reads patterns from a TOML file (version 3). You create it with `init`
```

---

### 7 — TOML example block (lines ~128–162)

This is the largest change. The entire ` ```toml ` block must be replaced.

**Current block** (between the ` ```toml ` and ` ``` ` markers, ~lines 129–162):
```toml
version = 2
registered = []

[[structural]]
identifier = "anthropic"
salt = "47abb6fb..."   # 64 hex chars (32 bytes)

[[structural.segments]]
type = "literal"
value = "sk-ant-api03-"

[[structural.segments]]
type = "variable"
charset = "url_safe_base64"
min = 93
max = 93

[[structural.segments]]
type = "literal"
value = "AA"

# ... more [[structural]] entries for other built-in classes ...

[[registered]]
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

**Replace the entire block content with:**
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

---

### 8 — Charset list after TOML block (lines ~164–165)

**Current:**
```markdown
Valid charset names for structural pattern segments: `alphanumeric`, `url_safe_base64`,
`uppercase_alphanumeric`, `digits`, `hex_lower`.
```

**Replace with:**
```markdown
Valid charset names for structural pattern segments: `alphanumeric`, `url_safe_base64`,
`uppercase_alphanumeric`, `digits`, `hex_lower`, `wide`.
```

(`wide` = 92 printable ASCII bytes: 0x21–0x7E excluding `"` and `\`; used by default for
registered-secret variable segments.)

---

### 9 — `register` CLI subsection (lines ~209–224)

Locate the `### \`register\` — register a secret` subsection. The shell command block
shows:
```sh
echo -n 'my-secret-value' | doppel register \
  --patterns secrets.toml \
  --label    my-api-key \
  [--preserve-prefix N] \
  [--preserve-suffix M] \
  [--restrict-charset]
```

And the following prose says `--label` is required.

**Replace the shell block with:**
```sh
echo -n 'my-secret-value' | doppel register \
  --patterns    secrets.toml \
  --identifier  my-api-key \
  [--anchor-len N] \
  [--tail-anchor-len M] \
  [--restrict-charset] \
  [--force]
```

**Replace the following prose paragraph** (currently says "`--label` is required..."):
```markdown
Reads the secret from stdin (raw bytes, no trimming), appends a new instance-pattern
entry to the patterns file, and writes it back atomically. The secret never appears in
command-line arguments. `--identifier` is required and must be unique within the file.

Alternatively, use `--group <id>` instead of `--identifier` to add this secret as an
additional digest to an existing group pattern (for grouping multiple secrets under one
detection rule).
```

Leave the `Source:` line unchanged.

---

### 10 — `list` CLI description (lines ~253–255)

**Current:**
```markdown
Prints a human-readable summary: structural pattern entries with identifier and segment
description; registered-secret entries with label, exact length, and charset summary. Does
not modify the file.
```

**Replace with:**
```markdown
Prints a human-readable summary: each `[[pattern]]` entry's identifier, kind (`family` or
`instance`), segment description, and digest count. Does not modify the file.
```

---

### 11 — `inspect` CLI subsection (lines ~257–267)

Locate the `### \`inspect\` — show detail for one pattern` subsection. The shell example
shows two lines:
```sh
doppel inspect --patterns secrets.toml --identifier anthropic
doppel inspect --patterns secrets.toml --label my-api-key
```
And the description says "Exactly one of `--identifier` (structural) or `--label`
(registered) is required."

**Replace the shell block with:**
```sh
doppel inspect --patterns secrets.toml --identifier anthropic
doppel inspect --patterns secrets.toml --identifier my-api-key
```

**Replace the description line** "Exactly one of `--identifier` (structural) or `--label`
(registered) is required." with:
```markdown
`--identifier` is required. Accepts any pattern kind (family or instance).
Prints full detail for the matched entry: all segments, salt fingerprint (first 8 hex
chars), kind, and digest count. Does not modify the file.
```

---

### 12 — `remove` CLI subsection (lines ~269–278)

Locate the `### \`remove\` — remove a pattern` subsection. The shell example shows:
```sh
doppel remove --patterns secrets.toml --identifier anthropic
doppel remove --patterns secrets.toml --label my-api-key
```
And the description says "Exactly one of `--identifier` (structural) or `--label`
(registered) is required."

**Replace the shell block with:**
```sh
doppel remove --patterns secrets.toml --identifier anthropic
doppel remove --patterns secrets.toml --identifier my-api-key
```

**Replace the "Exactly one of..." sentence with:**
```markdown
`--identifier` is required. Removes the specified entry and writes the file back
atomically. Removing a built-in structural pattern identifier emits a warning but
succeeds; `swap` will no longer detect that secret class.
```

---

### 13 — `For the paranoid` section at the end (lines ~299–309)

**Current:**
```markdown
## For the paranoid

Registered secrets are stored as a detection fingerprint — `start_fragment`,
`end_fragment`, `exact_length`, and `hmac_digest` (HMAC-SHA256 of the secret
against a per-registration salt) — never as the plaintext value. The source of
truth is [`doppel/src/secrets.rs`](doppel/src/secrets.rs).

You can verify any registered entry against its original secret using only
`openssl` and standard POSIX utilities, and independently reproduce the fake
doppel will generate. See [docs/for-the-paranoid.md](docs/for-the-paranoid.md)
for the full audit script and fake-derivation walkthrough.
```

**Replace with:**
```markdown
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
```

---

### 14 — Add `Detector` mention (library usage section)

Locate the `### Patterns file` subsection (around line 100) that contains the
`SecretsFile::deserialize` Rust code example. After the closing ` ``` ` of that example
block (and before the `**Create a new patterns file:**` heading), insert a new paragraph:

```markdown
For high-throughput use — many `swap` calls against the same pattern set — use
[`Detector`](https://docs.rs/doppel/latest/doppel/struct.Detector.html) to pre-build
the Aho-Corasick automaton once:

```rust
use doppel::{Detector, SecretsFile};

let data = std::fs::read("secrets.toml")?;
let sf = SecretsFile::deserialize(&data)?;
let patterns = sf.to_patterns()?;
let detector = Detector::new(&patterns);
// reuse `detector` across many requests
```

```

Adjust the blank lines to match the surrounding style.

## What NOT to change

- The `## How it works` diagram (except the box content as described in task 1)
- The `swap`, `restore`, `init` CLI sections (confirmed correct)
- The `## Streaming` and `## Async streaming` sections (confirmed correct)
- The `SecretsFile::deserialize` Rust example (confirmed correct)
- The `doppel init` create-a-new-file description
- The `define` CLI section (confirm charset list: if `wide` is missing, add it — check
  current content around line 241–242)

## Verify `define` charset list

Check around line 241–242 whether `wide` is already listed:
```markdown
Valid charset names: `alphanumeric`, `url_safe_base64`, `uppercase_alphanumeric`,
`digits`, `hex_lower`.
```

If `wide` is missing, add it to match the fix in task 8.

## Acceptance criteria

```sh
cd /home/ignacio/pr/doppel/.wt/spec-unified-pattern

# No v2 terminology remains:
! grep -n 'version = 2\|\[\[structural\]\]\|\[\[registered\]\]\|start_fragment\|end_fragment\|hmac_salt\|hmac_digest\|preserve_prefix\|preserve_suffix\|--label\b' README.md \
  && echo "STILL HAS V2 CONTENT" || echo "v2 content clean"

# v3 terminology present:
grep -q 'version = 3' README.md
grep -q '\[\[pattern\]\]' README.md
grep -q '\-\-identifier' README.md
grep -q '\-\-anchor-len' README.md
grep -q 'wide' README.md

# Rust doc tests (crate-level; README examples are not compiled, just check cargo clean):
cargo test --doc --workspace

# Full suite:
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
```

All commands must exit 0.

## Reviewer instructions

After the worker completes, verify:

1. ASCII diagram box says `[[pattern]]` (not `[[structural]]` or `[[registered]]`).
2. "Two kinds" sentence replaced with unified description.
3. Structural patterns paragraph mentions Opaque segment.
4. "27 providers" in the built-in list description.
5. `register` Rust example uses `anchor_len`/`tail_anchor_len`/`force` (no
   `preserve_prefix`/`preserve_suffix`).
6. "version 3" in patterns file intro.
7. TOML example block uses `[[pattern]]`, `[[pattern.segments]]`, `type = "opaque"` for
   instance segment, `digests = [...]`, and `version = 3`.
8. Charset list includes `wide`.
9. `register` CLI section uses `--identifier`, `--anchor-len`, `--tail-anchor-len`,
   `--group`, `--force` (no `--label`/`--preserve-prefix`/`--preserve-suffix`).
10. `list` description mentions `family`/`instance` kind and digest count.
11. `inspect` shows only `--identifier` (no `--label` alternative).
12. `remove` shows only `--identifier` (no `--label` alternative).
13. "For the paranoid" section uses v3 field names: `salt`, `opaque`, `digests`.
14. `Detector` is mentioned for high-throughput use.
15. `define` section charset list includes `wide`.
16. No section-separator comments introduced.
