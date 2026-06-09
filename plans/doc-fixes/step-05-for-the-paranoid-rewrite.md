# Step 05 — `docs/for-the-paranoid.md` rewrite

**Wave:** 3 (after Wave 2 — step-04 — completes)
**Status:** ⬜ pending

## Context

`docs/for-the-paranoid.md` (224 lines) describes how to independently audit a registered
secret. The entire file describes the v2 registration model (fields `start_fragment`,
`end_fragment`, `exact_length`, `hmac_salt`, `hmac_digest`; Python parser splitting on
`[[registered]]`; `LABEL` variable). None of these fields exist in v3.

The file must be rewritten from scratch for v3. **The structure and goal stays the same:**
explain exactly what is stored and provide a runnable audit script plus a fake-derivation
script. Only the field names, the verification logic, and the TOML parsing code change.

## Prerequisites

- Step-04 (README.md) must be ✅ complete
- `cargo nextest run --workspace` must pass before starting this step

## Files to read before writing

1. `doppel/src/secrets.rs` — read fully to understand what is stored in v3:
   - `SecretOptions` fields
   - `register_with_options_rng` function body (what it stores in the Pattern)
2. `doppel/src/fake.rs` — read the `derive_fake_for_instance` function
   (or whichever function handles instance-pattern fake generation) to understand the
   derivation algorithm. Focus on: how `seed` is computed, what `StdRng` is, and how
   anchor vs variable segments are drawn separately.
3. `secrets-example.toml` — the instance-pattern commented block near the end (after
   step-02 it now correctly shows `type = "opaque"` for the first segment).
4. `doppel/src/secrets_file.rs` — confirm the TOML key is `pattern` (not `patterns`) in
   `data["pattern"]` when loaded with `tomllib`.
5. `README.md` "For the paranoid" section (updated in step-04) for the brief summary that
   points here.

**Critical source facts** (verified against current HEAD `554c12e`):

### What v3 registration stores

A `[[pattern]]` entry for a registered secret contains:

| TOML field | Content |
|---|---|
| `identifier` | The string you supplied to `--identifier` |
| `salt` | 64 hex chars (32 bytes) — used for HMAC and fake derivation |
| `digests` | Array of 64-hex-char strings — `HMAC-SHA256(salt, full_secret)` per secret |
| `segments[0]` | `type = "opaque"`, `value` = first `anchor_len` bytes (default 3) verbatim, `charset` = charset detected from those bytes |
| `segments[1]` | `type = "variable"`, `min = max = (secret.len() - anchor_len - tail_anchor_len)` |

If `tail_anchor_len > 0`, there is a `segments[2]` of `type = "opaque"` for the trailing
anchor bytes.

### What verification checks (v3 audit)

Given the original secret:

1. **Total length**: `secret.len() == anchor_len + var_len [+ tail_anchor_len]` where
   `anchor_len = len(segments[0].value)` and `var_len = segments[1].min`.
2. **Anchor bytes**: `secret[:anchor_len] == bytes(segments[0].value)` (the opaque value
   field is the verbatim first bytes of the secret, UTF-8 encoded in TOML).
3. **HMAC digest**: `HMAC-SHA256(hex2bytes(salt), secret)` equals `hex2bytes(digests[0])`.

### Fake derivation (v3 algorithm)

From `doppel/src/fake.rs` (verify line numbers against current file before writing):

```
For attempt n (0-indexed, up to 1000):
  seed = HMAC-SHA256(salt, secret || n_as_le4_bytes)
  rng  = StdRng::from_seed(seed)   # StdRng = ChaCha12 in rand 0.8

For the opaque segment (anchor_len bytes):
  charset = detected charset of anchor bytes (or stored charset override)
  Draw anchor_len bytes from charset using rejection sampling on u32 keystream words.

For the variable segment (var_len bytes):
  charset = wide (92 printable ASCII, 0x21–0x7E excluding '"' and '\')
            unless --restrict-charset was set, in which case charset = anchor's charset
  Draw var_len bytes from charset using rejection sampling.

If the full fake == the original secret, increment n and retry.
```

`StdRng` is `ChaCha12Rng` (24-round variant in some documents is ChaCha12 in rand 0.8 —
verify in `doppel/src/fake.rs` imports). The `for-the-paranoid.md` Rust script uses
`rand_chacha::ChaCha12Rng` which is correct.

**Key difference from v2**: the fake is generated per-segment (anchor separately from
variable), not as one flat pass over the whole secret length.

## What to write

Rewrite the file completely. Keep the same top-level structure:

1. Opening paragraph explaining the purpose
2. `## What registration stores` — table of v3 fields
3. `## Audit script` — bash script using `openssl`, `python3`, and `xxd` to verify
   the three claims above
4. `## Fake derivation (optional)` — rust-script for reproducing the fake

The file must be accurate and runnable by a cautious user. Comments in scripts are
essential. Do not add decorative section separators.

---

## Required content (write this exactly)

### Opening paragraph

```markdown
# For the paranoid

After `doppel register` writes a `[[pattern]]` entry to your patterns file,
you should be able to verify it against the original secret using nothing but
`openssl`, `python3`, and standard POSIX utilities — no trust in the doppel binary
required.
```

### `## What registration stores`

```markdown
## What registration stores

| Field | Content |
|---|---|
| `identifier` | The string you passed to `--identifier` |
| `salt` | 64 hex chars (32 bytes) — per-registration random value |
| `digests[0]` | `HMAC-SHA256(salt, full_secret)` — 64 hex chars |
| `segments[0].type` | `"opaque"` — detection anchor |
| `segments[0].value` | First `anchor_len` bytes of the secret (UTF-8 string) |
| `segments[1].type` | `"variable"` — variable portion |
| `segments[1].min` | Byte count of the variable portion (`secret.len() - anchor_len`) |

The plaintext secret is never stored. The `digests` array may hold more than one entry
when multiple secrets are grouped under one identifier (`doppel register --group`).
```

### `## Audit script`

The script must:

1. Accept two positional args: `<patterns-file>` and `<identifier>`.
2. Read the secret from stdin.
3. Parse the TOML file with `python3 tomllib` (stdlib since Python 3.11; fall back to
   `pip install tomli` for older versions).
4. Locate the entry by `identifier` in `data["pattern"]`.
5. Perform three checks:
   a. `anchor_check`: `secret[:anchor_len] == entry["segments"][0]["value"].encode()`
   b. `length_check`: `len(secret) == anchor_len + var_len` where
      `anchor_len = len(entry["segments"][0]["value"])` and
      `var_len = entry["segments"][1]["min"]`
   c. `hmac_check`: `HMAC-SHA256(bytes.fromhex(entry["salt"]), secret) == bytes.fromhex(entry["digests"][0])`
6. Print ✓/✗ for each check and exit 1 if any fail.

Write the script as a bash script that invokes `python3 -c` for the TOML parsing and
HMAC computation, and uses `openssl` for a cross-check of the HMAC. Include both the
Python-based check and an `openssl dgst` cross-check.

Template structure (fill in the Python and openssl commands):

```bash
#!/usr/bin/env bash
# Usage: echo -n 'my-secret' | bash audit.sh secrets.toml my-identifier
# Requires: python3 (3.11+ for tomllib, or install tomli), openssl, xxd
set -euo pipefail

PATTERNS_FILE="${1:?usage: $0 <patterns-file> <identifier>}"
IDENTIFIER="${2:?usage: $0 <patterns-file> <identifier>}"

SECRET_FILE=$(mktemp)
trap 'rm -f "$SECRET_FILE"' EXIT
cat > "$SECRET_FILE"

SECRET_LEN=$(wc -c < "$SECRET_FILE" | tr -d ' ')
[[ $SECRET_LEN -gt 0 ]] || { echo 'error: empty secret' >&2; exit 1; }

# Extract fields from the patterns file using python3.
read -r STORED_SALT STORED_DIGEST ANCHOR_VALUE VAR_MIN < <(python3 -c "
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib  # pip install tomli for Python < 3.11
data = tomllib.load(open('$PATTERNS_FILE', 'rb'))
entry = next((e for e in data['pattern'] if e['identifier'] == '$IDENTIFIER'), None)
if entry is None:
    print('no entry with identifier: $IDENTIFIER', file=sys.stderr)
    sys.exit(1)
seg0 = entry['segments'][0]
seg1 = entry['segments'][1]
print(entry['salt'], entry['digests'][0], seg0['value'], seg1['min'])
")

ANCHOR_LEN=${#ANCHOR_VALUE}

PASS=0; FAIL=0
check() {
  local desc="\$1" computed="\$2" stored="\$3"
  if [[ "\$computed" == "\$stored" ]]; then
    echo "  ✓ \$desc"; PASS=$(( PASS + 1 ))
  else
    echo "  ✗ \$desc"; echo "      stored:   \$stored"; echo "      computed: \$computed"
    FAIL=$(( FAIL + 1 ))
  fi
}

echo "Auditing '$IDENTIFIER' in $PATTERNS_FILE"

# 1. Total length: anchor_len + var_len == secret_len
EXPECTED_LEN=$(( ANCHOR_LEN + VAR_MIN ))
check length "$SECRET_LEN" "$EXPECTED_LEN"

# 2. Anchor bytes: first anchor_len bytes of secret == segments[0].value
COMPUTED_ANCHOR=$(head -c "$ANCHOR_LEN" "$SECRET_FILE" | cat)
check anchor "$COMPUTED_ANCHOR" "$ANCHOR_VALUE"

# 3. HMAC-SHA256(salt, secret) == digests[0]
COMPUTED_HMAC=$(openssl dgst -sha256 -mac HMAC \
  -macopt "hexkey:${STORED_SALT}" "$SECRET_FILE" | awk '{print $NF}')
check hmac_digest "$COMPUTED_HMAC" "$STORED_DIGEST"

echo
if [[ $FAIL -eq 0 ]]; then
  echo "all $PASS checks passed"
else
  echo "$FAIL check(s) failed" >&2; exit 1
fi
```

**Note to worker**: the `COMPUTED_ANCHOR` comparison must handle non-printable bytes
correctly. If the anchor might contain bytes outside 0x20–0x7E, use `xxd` or `od` to
compare hex representations instead of a plain string comparison. For simplicity, document
this limitation in a comment and compare hex:

```bash
# 2. Anchor bytes: compare as hex to handle non-printable bytes safely
COMPUTED_ANCHOR_HEX=$(head -c "$ANCHOR_LEN" "$SECRET_FILE" | xxd -p | tr -d '\n')
STORED_ANCHOR_HEX=$(printf '%s' "$ANCHOR_VALUE" | xxd -p | tr -d '\n')
check anchor_hex "$COMPUTED_ANCHOR_HEX" "$STORED_ANCHOR_HEX"
```

Use this hex form instead of the plain string form. Update the `check` call accordingly.

### `## Fake derivation (optional)`

Keep the same structure as the existing section: explain the derivation algorithm in prose,
then provide a `rust-script` example.

**Prose description:**

```markdown
## Fake derivation (optional)

To reproduce the fake doppel will generate — to confirm the substitution before it
happens — you need a seeded ChaCha12 RNG. No mainstream crypto toolkit ships ChaCha12
except [**Botan**](https://botan.randombit.net/) or the Rust `rand_chacha` crate.

The v3 derivation for attempt `n` (starting at 0):

1. `seed = HMAC-SHA256(salt, secret || n_le4)` where `n_le4` is `n` as a 4-byte
   little-endian integer.
2. Initialize ChaCha12 with `seed` as the 32-byte key
   (`rand_chacha::ChaCha12Rng::from_seed(seed)`).
3. For the **opaque segment** (first `anchor_len` bytes):
   draw bytes from the anchor's detected charset using rejection sampling on u32 words:
   `threshold = u32::MAX - (u32::MAX % |charset|)`;
   accept `r` if `r < threshold` and emit `charset[r % |charset|]`.
4. For the **variable segment** (remaining bytes):
   draw from the `wide` charset (92 printable ASCII: 0x21–0x7E excluding `"` and `\`),
   unless `--restrict-charset` was used, in which case use the anchor's charset.
5. If the result equals the original secret, increment `n` and retry (up to 1 000 times).
```

**Rust script** (update from v2 to v3 — the key changes are: separate anchor/variable
passes, `IDENTIFIER` instead of `LABEL`, TOML key is `data["pattern"]`):

```rust
#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! hmac        = "0.12"
//! sha2        = "0.10"
//! rand_chacha = "0.3"
//! rand_core   = "0.6"
//! hex         = "0.4"
//! ```
use hmac::{Hmac, Mac};
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::Sha256;
use std::io::Read;

fn wide_charset() -> Vec<u8> {
    (0x21u8..=0x7E).filter(|&b| b != b'"' && b != b'\\').collect()
}

fn alphanumeric_charset() -> Vec<u8> {
    let mut v: Vec<u8> = (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9').collect();
    v
}

fn draw_bytes(rng: &mut ChaCha12Rng, charset: &[u8], n: usize) -> Vec<u8> {
    let cs_len = charset.len() as u32;
    let threshold = u32::MAX - (u32::MAX % cs_len);
    (0..n).map(|_| {
        loop {
            let r = rng.next_u32();
            if r < threshold { return charset[(r % cs_len) as usize]; }
        }
    }).collect()
}

fn derive_fake(
    salt: &[u8; 32],
    secret: &[u8],
    anchor_len: usize,
    anchor_charset: &[u8],
    var_charset: &[u8],
) -> Option<Vec<u8>> {
    let var_len = secret.len() - anchor_len;
    for attempt in 0u32..1_000 {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).unwrap();
        mac.update(secret);
        mac.update(&attempt.to_le_bytes());
        let seed: [u8; 32] = mac.finalize().into_bytes().into();
        let mut rng = ChaCha12Rng::from_seed(seed);
        let mut fake = draw_bytes(&mut rng, anchor_charset, anchor_len);
        fake.extend(draw_bytes(&mut rng, var_charset, var_len));
        if fake != secret { return Some(fake); }
    }
    None
}

fn main() {
    let salt_hex = std::env::args().nth(1)
        .expect("usage: derive_fake <salt_hex> <anchor_len>");
    let anchor_len: usize = std::env::args().nth(2)
        .expect("usage: derive_fake <salt_hex> <anchor_len>")
        .parse().expect("anchor_len must be an integer");
    let salt: [u8; 32] = hex::decode(&salt_hex)
        .expect("invalid hex")
        .try_into()
        .expect("salt must be 32 bytes");
    let mut secret = Vec::new();
    std::io::stdin().read_to_end(&mut secret).unwrap();

    // Use alphanumeric as anchor charset (adjust if your secret uses a different charset).
    let anchor_charset = alphanumeric_charset();
    let var_charset = wide_charset();

    match derive_fake(&salt, &secret, anchor_len, &anchor_charset, &var_charset) {
        Some(fake) => std::io::Write::write_all(&mut std::io::stdout(), &fake).unwrap(),
        None => { eprintln!("collision limit exceeded"); std::process::exit(1); }
    }
}
```

Usage line:
```sh
echo -n 'my-secret-value' | rust-script derive_fake.rs <salt_hex> <anchor_len>
```

Add a note that `anchor_charset` in the script defaults to `alphanumeric`; to match
exactly, check `segments[0].charset` in the patterns file and replace accordingly.

---

## Acceptance criteria

```sh
cd /home/ignacio/pr/doppel/.wt/spec-unified-pattern

# No v2 terminology remains in the file:
! grep -n 'start_fragment\|end_fragment\|hmac_salt\|hmac_digest\|\[\[registered\]\]\|LABEL\b' \
    docs/for-the-paranoid.md && echo "STILL HAS V2 CONTENT" || echo "v2 content clean"

# v3 terminology present:
grep -q 'identifier' docs/for-the-paranoid.md
grep -q 'digests\[0\]' docs/for-the-paranoid.md
grep -q 'opaque' docs/for-the-paranoid.md

# Full test suite still passes:
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Reviewer instructions

After the worker completes, verify:

1. File opens with "After `doppel register` writes a `[[pattern]]` entry..."
   (not `[[registered]]`).
2. The "What registration stores" table lists `salt`, `digests[0]`, `segments[0].type =
   opaque`, `segments[0].value`, `segments[1].min` — no v2 fields.
3. The audit bash script:
   - Uses `IDENTIFIER` (not `LABEL`) for the positional argument.
   - Parses TOML via `data["pattern"]` (not `text.split("[[registered]]")`).
   - Compares anchor bytes using hex (not raw string comparison).
   - Runs `HMAC-SHA256(salt, secret)` against `digests[0]`.
   - Has three checks: length, anchor, HMAC.
4. The fake-derivation Rust script:
   - Uses `ChaCha12Rng` (not `ChaCha20Rng` or another variant).
   - Has two separate `draw_bytes` calls — one for anchor segment, one for variable.
   - Accepts `<salt_hex>` and `<anchor_len>` as command-line args.
5. No section-separator comments introduced (`// ---`, `// ===`, etc.).
6. No v2 fields (`start_fragment`, `end_fragment`, `hmac_salt`, `hmac_digest`,
   `[[registered]]`, `LABEL`) remain anywhere in the file.
