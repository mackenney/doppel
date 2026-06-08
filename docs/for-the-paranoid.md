# For the paranoid

After `doppel register` writes a `[[pattern]]` entry to your patterns file,
you should be able to verify it against the original secret using nothing but
`openssl`, `python3`, and standard POSIX utilities — no trust in the doppel binary
required.

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

## Audit script

Save the following as `audit.sh`, then run:

```sh
echo -n 'my-secret-value' | bash audit.sh secrets.toml my-identifier
```

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
  local desc="$1" computed="$2" stored="$3"
  if [[ "$computed" == "$stored" ]]; then
    echo "  ✓ $desc"; PASS=$(( PASS + 1 ))
  else
    echo "  ✗ $desc"; echo "      stored:   $stored"; echo "      computed: $computed"
    FAIL=$(( FAIL + 1 ))
  fi
}

echo "Auditing '$IDENTIFIER' in $PATTERNS_FILE"

# 1. Total length: anchor_len + var_len == secret_len
EXPECTED_LEN=$(( ANCHOR_LEN + VAR_MIN ))
check length "$SECRET_LEN" "$EXPECTED_LEN"

# 2. Anchor bytes: compare as hex to handle non-printable bytes safely
COMPUTED_ANCHOR_HEX=$(head -c "$ANCHOR_LEN" "$SECRET_FILE" | xxd -p | tr -d '\n')
STORED_ANCHOR_HEX=$(printf '%s' "$ANCHOR_VALUE" | xxd -p | tr -d '\n')
check anchor_hex "$COMPUTED_ANCHOR_HEX" "$STORED_ANCHOR_HEX"

# 3. HMAC-SHA256(salt, secret) == digests[0]
COMPUTED_HMAC=$(openssl dgst -sha256 -mac HMAC \
  -macopt "hexkey:${STORED_SALT}" "$SECRET_FILE" | awk '{print $NF}')
check hmac "$COMPUTED_HMAC" "$STORED_DIGEST"

echo
if [[ $FAIL -eq 0 ]]; then
  echo "all $PASS checks passed"
else
  echo "$FAIL check(s) failed" >&2; exit 1
fi
```

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

Save the following as `derive_fake.rs` and run with `rust-script`:

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
    (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9').collect()
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
    // Check segments[0].charset in the patterns file to match exactly.
    let anchor_charset = alphanumeric_charset();
    let var_charset = wide_charset();

    match derive_fake(&salt, &secret, anchor_len, &anchor_charset, &var_charset) {
        Some(fake) => std::io::Write::write_all(&mut std::io::stdout(), &fake).unwrap(),
        None => { eprintln!("collision limit exceeded"); std::process::exit(1); }
    }
}
```

Usage:

```sh
echo -n 'my-secret-value' | rust-script derive_fake.rs <salt_hex> <anchor_len>
```

`anchor_charset` in the script defaults to `alphanumeric`; to match exactly, check
`segments[0].charset` in the patterns file and replace accordingly.
