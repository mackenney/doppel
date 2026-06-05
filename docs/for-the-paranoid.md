# For the paranoid

After `doppel register` writes a `[[registered]]` entry to your patterns file,
you should be able to verify it against the original secret using nothing but
`openssl` and standard POSIX utilities — no trust in the doppel binary required.

## What registration stores

| Field | Content |
|---|---|
| `start_fragment` | First 8 bytes of the secret (hex) — detection anchor |
| `end_fragment` | Last 8 bytes of the secret (hex) — detection anchor |
| `exact_length` | Total byte length |
| `hmac_salt` | 32 random bytes (hex) — unique per registration |
| `hmac_digest` | HMAC-SHA256(hmac\_salt, secret) (hex) — confirmation token |

The confirmation token is the only link between the stored entry and the original
secret. A candidate that passes the start/end fragment and length checks but
fails the HMAC is passed through unchanged.

## Audit script

Reads the secret from stdin, extracts the entry from the patterns file by label,
and checks all four claims independently.

```bash
#!/usr/bin/env bash
# Usage: echo -n 'my-secret' | bash audit.sh secrets.toml my-label
# Requires: openssl, xxd, python3
set -euo pipefail

PATTERNS_FILE="${1:?usage: $0 <patterns-file> <label>}"
LABEL="${2:?usage: $0 <patterns-file> <label>}"

SECRET_FILE=$(mktemp)
trap 'rm -f "$SECRET_FILE"' EXIT
cat > "$SECRET_FILE"

SECRET_LEN=$(wc -c < "$SECRET_FILE" | tr -d ' ')
[[ $SECRET_LEN -gt 0 ]] || { echo 'error: empty secret' >&2; exit 1; }

# Extract a field from the [[registered]] block with the given label.
field() {
  python3 -c "
text = open('$PATTERNS_FILE').read()
for block in text.split('[[registered]]'):
    if 'label = \"$LABEL\"' in block:
        for line in block.splitlines():
            k, _, v = line.partition(' = ')
            if k.strip() == '$1':
                print(v.strip().strip('\"'))
                break
"
}

STORED_START=$(field start_fragment)
STORED_END=$(field end_fragment)
STORED_LEN=$(field exact_length)
HMAC_SALT=$(field hmac_salt)
HMAC_DIGEST=$(field hmac_digest)

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

echo "Auditing '$LABEL' in $PATTERNS_FILE"

# 1. exact_length
check exact_length "$SECRET_LEN" "$STORED_LEN"

# 2. start_fragment: first min(8, len) bytes
START_BYTES=$(( SECRET_LEN < 8 ? SECRET_LEN : 8 ))
COMPUTED_START=$(head -c "$START_BYTES" "$SECRET_FILE" | xxd -p | tr -d '\n')
check start_fragment "$COMPUTED_START" "$STORED_START"

# 3. end_fragment: last min(8, remaining) bytes
REMAINING=$(( SECRET_LEN - START_BYTES ))
END_BYTES=$(( REMAINING < 8 ? REMAINING : 8 ))
if [[ $END_BYTES -gt 0 ]]; then
  COMPUTED_END=$(tail -c "$END_BYTES" "$SECRET_FILE" | xxd -p | tr -d '\n')
else
  COMPUTED_END=""
fi
check end_fragment "$COMPUTED_END" "$STORED_END"

# 4. hmac_digest: HMAC-SHA256(hmac_salt, secret)
COMPUTED_HMAC=$(openssl dgst -sha256 -mac HMAC \
  -macopt "hexkey:${HMAC_SALT}" "$SECRET_FILE" | awk '{print $NF}')
check hmac_digest "$COMPUTED_HMAC" "$HMAC_DIGEST"

echo
if [[ $FAIL -eq 0 ]]; then
  echo "all $PASS checks passed"
else
  echo "$FAIL check(s) failed" >&2; exit 1
fi
```

## Fake derivation (optional)

If you also want to reproduce the fake doppel will generate — to confirm the
substitution before it happens — the derivation uses a seeded ChaCha12 RNG.
No mainstream crypto toolkit ships ChaCha12 except
[**Botan**](https://botan.randombit.net/) (`apt install botan2` on Debian/Ubuntu).

The derivation for attempt `n` (starting at 0):

1. `seed = HMAC-SHA256(hmac_salt, secret || n_le4)` where `n_le4` is `n` as a
   4-byte little-endian integer.
2. Initialize ChaCha12 ("djb" variant: key = seed, nonce = 8 zero bytes,
   counter = 0).
3. Draw u32 words from the keystream; for each position, accept `r` if
   `r < threshold` where `threshold = 0xFFFFFFFF - (0xFFFFFFFF % |charset|)`
   and emit `charset[r % |charset|]`.
4. If the result equals the original, increment `n` and retry (up to 1 000 times).

As a [`rust-script`](https://rust-script.org/) (`cargo install rust-script`):

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

fn derive_fake(salt: &[u8; 32], secret: &[u8], charset: &[u8]) -> Option<Vec<u8>> {
    let n   = charset.len() as u32;
    let thr = u32::MAX - (u32::MAX % n);
    for attempt in 0u32..1_000 {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).unwrap();
        mac.update(secret);
        mac.update(&attempt.to_le_bytes());
        let seed: [u8; 32] = mac.finalize().into_bytes().into();
        let mut rng  = ChaCha12Rng::from_seed(seed);
        let mut fake = Vec::with_capacity(secret.len());
        for _ in 0..secret.len() {
            let idx = loop {
                let r = rng.next_u32();
                if r < thr { break (r % n) as usize; }
            };
            fake.push(charset[idx]);
        }
        if fake != secret { return Some(fake); }
    }
    None
}

fn main() {
    let salt_hex = std::env::args().nth(1)
        .expect("usage: derive_fake <hmac_salt_hex>");
    let salt: [u8; 32] = hex::decode(&salt_hex)
        .expect("invalid hex")
        .try_into()
        .expect("hmac_salt must be 32 bytes");
    let mut secret = Vec::new();
    std::io::stdin().read_to_end(&mut secret).unwrap();
    match derive_fake(&salt, &secret, &wide_charset()) {
        Some(fake) => std::io::Write::write_all(&mut std::io::stdout(), &fake).unwrap(),
        None => { eprintln!("collision limit exceeded"); std::process::exit(1); }
    }
}
```

```sh
echo -n 'my-secret-value' | rust-script derive_fake.rs <hmac_salt_hex>
```
