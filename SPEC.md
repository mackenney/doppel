# doppel — Specification

> The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are used per RFC 2119.

## Purpose

`doppel` intercepts secrets in arbitrary byte payloads, replaces them with structurally-equivalent fakes, and transparently restores the originals in the corresponding output stream — including streaming responses. The threat it addresses is accidental secret exfiltration: secrets that end up in outbound payloads — for example, LLM request bodies — through normal development work (tool output, file contents, environment variables, debug context). Detection is exact and deterministic: any byte sequence matching a declared pattern is replaced without exception, unless that pattern explicitly opts into trailing-run-guard suppression (see §Trailing Run Guard). Coverage is limited in the sense that secrets split, base64-encoded, obfuscated, or otherwise transformed before the payload is formed are out of scope; it makes no claim about coverage of transformed forms.

## Non-Goals

- Detecting secrets that are deliberately obfuscated, split, base64-encoded, or otherwise transformed before reaching the payload.
- System-wide network interception (TLS MITM, packet filtering, iptables redirect).
- PII detection, GDPR compliance, or any regulatory-compliance goal.
- Persistent storage of original secrets.
- Coverage of every form a secret can take: exact pattern matching is the contract; obfuscated, encoded, or split secrets are out of scope by design.
- Header inspection; scope is request and response body bytes only.
- Multi-hop or nested swap/restore chains.
- Defense against a compromised host or a malicious caller with access to process memory.

## Core Mental Model

The library's surface area is defined by three operations and three data abstractions:

**Pattern** is a detection descriptor. It encapsulates everything needed to find a specific secret or secret class in an arbitrary payload and replace it with a structurally-equivalent fake. A Pattern is defined by three fields: an ordered segment list that describes what bytes to look for, a stable salt that drives deterministic fake derivation, and an optional list of HMAC digests that constrains detection to a specific set of secret instances. The segment list and salt are mandatory. The digest list is optional: an empty list means the Pattern matches any byte sequence that satisfies the segment structure (a _family_ pattern); a non-empty list means the Pattern additionally requires that the candidate's HMAC matches one of the stored digests (an _instance_ or _group_ pattern).

Both built-in structural patterns (Anthropic, OpenAI, etc.) and user-registered secrets produce Pattern values. `swap` treats all Patterns uniformly — it is not aware of which kind produced each Pattern.

**`swap`** receives a complete payload and a set of Patterns. It scans for secrets left-to-right, replaces each detected secret with the fake prescribed by the matching Pattern, and returns three things: the swapped payload, a set of substitution **entries**, and a **session key**. `swap` MUST NOT modify bytes outside the detected secrets. `swap` accepts a single complete payload buffer; streaming input is not part of the API.

**Entries** are the set of substitution records produced by one `swap` call — one record per distinct secret detected. Each entry holds the fake bytes and the ciphertext of the original secret, encrypted under the session key. Entries are not confidentiality-sensitive on their own: without the session key, the ciphertext is opaque. An observer who sees the entries learns the exact byte length of each detected secret. No plaintext secret bytes appear in entries. The session key remains the sole decryption gate.

**Session key** is a 32-byte random value generated fresh at `swap` time. It is the sole decryption gate for the entries produced in that call. The session key is sensitive and ephemeral: it exists in process memory for one swap/restore cycle only, MUST NOT be written to disk, and MUST NOT appear in logs or any serialized form. Entries and session key are explicitly separate values with separate sensitivity levels and separate lifetimes.

**`restore`** receives a response stream, the entries from the corresponding `swap` call, and the session key. It performs exact multi-string matching using only the fake byte strings in the entries — no pattern detection, no charset scanning. Every match triggers decryption of the corresponding entry; the original bytes are emitted in place of the fake. Bytes that do not match any fake are forwarded unchanged. `restore` MUST NOT require the full response to be buffered before emitting output.

**Registration** is a preparatory operation that takes a secret value and produces an instance Pattern. The secret is consumed during registration and immediately discarded; the library has no persistent store. The produced Pattern is an opaque value the caller holds and passes to future `swap` calls.

**`Detector`** is a pre-built detection context. It encapsulates a set of Patterns and the Aho-Corasick automaton derived from their first segments, built once at construction. `Detector::swap` has identical semantics to the free `swap` function but reuses the pre-built automaton across calls. `Detector` is `Send + Sync` and intended for use in long-running processes where the pattern set is fixed at startup.

These operations and data abstractions are the complete public surface.

## Pattern Detection

### Segment Types

A Pattern's detection structure is an ordered sequence of segments. Each segment is one of three types:

**`literal`** — a fixed byte sequence. At detection time, the payload bytes at the current position must exactly equal the segment's value. In fake generation, the literal bytes are reproduced verbatim at the corresponding position. Use `literal` for bytes that are structurally required by the external system (e.g., the `sk-ant-api03-` prefix of an Anthropic key) or for bytes that the caller explicitly declares non-secret and wants preserved in the fake.

**`opaque`** — a fixed byte sequence used as a detection anchor. At detection time, the payload bytes at the current position must exactly equal the segment's value — identical to `literal`. In fake generation, the opaque segment's bytes are _derived_ rather than reproduced verbatim: the fake bytes at those positions are drawn from the segment's charset (default: the minimal charset detected from the segment's own value bytes). Use `opaque` for bytes that the caller wants to anchor detection to but does not want to expose in the fake — typically the leading bytes of a secret that should appear opaque to the upstream system.

**`variable`** — a constrained variable-length region. At detection time, the bytes at the current position must all belong to the segment's charset, and the consumed byte count must fall within `[min, max]`. When a `variable` segment is followed by a `literal` or `opaque` segment, the boundary is found by searching for the next segment's value within the valid length range — this handles embedded fixed markers within an otherwise variable region. In fake generation, the fake bytes are drawn from the segment's charset, derived deterministically from the Pattern's salt and the matched candidate.

### First-Segment Invariant

The first segment of every Pattern MUST be either a `literal` or an `opaque` segment. Patterns whose first segment is `variable` MUST be rejected at load and registration time with a clear error. This invariant ensures that every Pattern contributes a fixed byte anchor to the combined Aho-Corasick automaton used during `swap`, eliminating the need for byte-by-byte fallback scanning.

### Family vs Instance Patterns

A Pattern with an empty `digests` list is a **family pattern**: it detects every byte sequence that satisfies the segment structure, regardless of content. Family patterns are appropriate for well-known secret formats where any key of that format should be protected (e.g., any Anthropic API key, any GitHub PAT).

A Pattern with a non-empty `digests` list is an **instance or group pattern**: after the segment structure is satisfied, detection additionally requires that `HMAC(salt, candidate)` matches at least one digest in the list. If no digest matches, the candidate is passed through unchanged — no replacement occurs. Instance patterns are appropriate for protecting specific known secret values without protecting all secrets of the same format.

All digests in a single Pattern share the same salt. This allows a single HMAC computation per candidate to be compared against all digests in the list, regardless of group size. Each digest corresponds to one registered secret; distinct secrets produce distinct digests under the same salt.

### Detection Algorithm in `swap`

`swap` builds a combined Aho-Corasick automaton from the leading byte values of the first segment of every Pattern (both `literal` and `opaque` first segments contribute). This automaton locates positions in the payload where any Pattern could begin. All bytes between candidate positions are bulk-copied to the output unchanged.

At each candidate position, `swap` attempts every Pattern whose first segment matches:

1. Walk the segment list against the payload at the candidate position. A `literal` or `opaque` segment must match its exact bytes. A `variable` segment must find a valid length within its range such that all bytes are in the charset and the next segment (if any) also matches.
2. If segment matching fails, move to the next Pattern. If all Patterns fail, advance one byte.
3. If segment matching succeeds and the Pattern has no digests (family): the candidate is accepted.
4. If segment matching succeeds and the Pattern has digests (instance/group): compute `HMAC(salt, candidate)` once and compare against each digest using constant-time equality. If any digest matches, the candidate is accepted. If none match, the candidate is rejected and passed through unchanged.
5. Among all Patterns that accept the candidate, the one producing the longest match wins (leftmost-longest). If two Patterns match with the same length, the `literal`-first Pattern takes precedence over the `opaque`-first Pattern. If the tie persists (same match length, same first-segment kind), a Pattern that declares a trailing run guard (see §Trailing Run Guard) takes precedence over one that does not; if both declare a guard, the Pattern with the larger threshold takes precedence.
6. If the winning Pattern declares a trailing run guard and the guard fires (see §Trailing Run Guard), the position yields no detection — scanning proceeds exactly as if all Patterns had failed at this position. Losing candidates from step 5 are not reconsidered.

### Trailing Run Guard

A Pattern MAY declare a **trailing run guard**: a positive minimum trailing same-charset run length, expressed as a byte count threshold. The guard defends against false positives that arise when a pattern's structure is statistically weak relative to large charset-uniform data: a short fixed prefix followed by a single variable region whose charset is a base64 alphabet can occur by accident inside large base64-encoded blobs (for example, image data embedded in a request body). Under an idealized model that treats base64-encoded binary as i.i.d. uniform symbols, a 4-byte prefix occurs by chance roughly once per 64⁴ ≈ 16.7 million bytes, and once it does, the following variable region is satisfied almost for free because the surrounding blob is drawn from the same charset. This is an order-of-magnitude estimate, not a measured rate, but it is enough to make such false positives routine in payloads carrying megabytes of encoded binary data — and each false replacement corrupts the encoded data.

The intuition: a genuine standalone secret is delimited by its surrounding context (quotes, whitespace, structural punctuation) within a short distance of its end. A "match" whose trailing context continues in the same charset for thousands of bytes is overwhelmingly likely to be a slice of an encoded blob, not a secret.

**Charset resolution.** A pattern MAY declare the guard charset explicitly, as an optional guard-charset property separate from every segment's charset. When declared, the guard probe uses exactly the declared charset. When absent, the guard charset is inferred as the charset of the pattern's last `variable` segment. A pattern that declares a trailing run guard with no explicit guard charset and no `variable` segment MUST be rejected at patterns-file load time with a clear error; when an explicit guard charset is declared, no `variable` segment is required — the guard is usable on all-literal/opaque patterns. The no-variable-segment failure mode cannot arise through registration: every registered secret's Pattern contains exactly one `variable` segment by construction (see §Registration). Registration-time guard validation covers the threshold and, when supplied, the optional explicit guard charset (see §Registration Options).

The explicit declaration exists because inference conflates two distinct charsets that usually coincide but can diverge: the _match charset_ — what a genuine secret's variable region looks like — and the _noise charset_ — what the surrounding blob that causes false positives looks like. The built-in GCP pattern is the motivating divergence: real GCP keys never contain `+` or `/`, so its match charset is correctly `url_safe_base64`, but the encoded blobs that cause its false positives are overwhelmingly standard-alphabet base64, in which the first `+` or `/` byte terminates a url-safe run far short of any useful threshold (measured 0-148 bytes across real false positives) — an inferred guard charset can never accumulate a useful threshold there, and the guard cannot fire against its own primary target. Pattern authors SHOULD choose an explicit guard charset that models the actual noise being defended against, and SHOULD NOT declare a charset broader than that noise (e.g. `wide`): an overly broad guard charset counts ordinary trailing prose or structural bytes toward the run and over-suppresses genuine secrets, enlarging the accepted false-negative class (see §Known Limitations).

**Suppression rule.** After a pattern produces the winning match at a position (per step 5 of the detection algorithm), the bytes immediately following the match end are probed forward. If at least the declared threshold count of consecutive bytes all belong to the guard charset, the match MUST be discarded — treated as no detection at this position. If end of payload or a byte outside the charset is reached before the threshold count is accumulated, the match stands. Suppression is a binary threshold decision: there is no partial or probabilistic suppression. The probe is forward-only — bytes preceding the match start are never examined — and it MAY stop reading as soon as the threshold is reached; it need not measure the full run length.

**Selection order.** The guard applies only to the single winning match already selected by the leftmost-longest rule (Behavioral Invariants item 18). Competing structural matches at the same starting position that lost that tie-break MUST NOT be reconsidered when the winner is suppressed: suppression yields no detection at that position, full stop, with no cascade to a next-best match. Consequently, when two structurally overlapping patterns coexist and only the longer one is guarded, a suppressed long match does not fall back to the shorter unguarded pattern at the same position; keeping guard configuration consistent across overlapping patterns is the pattern author's responsibility.

**Tie-breaking.** Beyond suppression, guard declaration participates in match selection as the lowest-priority tie-break (Behavioral Invariants item 18). It is consulted only when two candidates are already tied under every higher-priority rule — same match-end position and same first-segment kind: a guarded pattern then wins over an unguarded one, and between two guarded patterns the larger threshold wins. The threshold preference is deliberately conservative and security-first, and the reasoning is not self-evident: a larger threshold is harder to satisfy — more trailing same-charset bytes are required before suppression fires — so preferring it on tie selects the configuration least likely to ever suppress a detection. This biases ambiguous ties toward detection, consistent with the threat model in which a missed real secret is a worse outcome than a tolerated false positive.

**Independence.** Evaluation of one pattern's guard MUST depend only on that pattern's own declaration, its own match boundaries, and the payload bytes in its forward probe window. It MUST NOT depend on any other pattern's configuration, nor on any match or suppression decision at any other position. The probe examines trailing bytes solely for charset membership; whether those bytes happen to belong to another pattern's genuine secret is irrelevant to the probe, and that other secret remains independently detectable at its own starting position with unchanged semantics.

**Opt-in.** Absence of the property changes nothing: a pattern with no trailing run guard retains the exact, unconditional detection contract stated in §Purpose.

### Built-in Family Patterns

The library MUST ship built-in family pattern definitions covering at minimum: Anthropic API keys, OpenAI API keys (classic, project, service account), AWS IAM access key IDs (AKIA and ASIA prefixes), GitHub personal access tokens (classic, fine-grained, OAuth, app server, app user, refresh), GCP API keys, OpenRouter keys, Google OAuth client secrets, Slack bot tokens, Linear API keys, Groq, Perplexity, Cerebras, Stripe, Clerk, Svix, and Chromatic. Additional definitions MAY be added; the built-in set is not closed.

The built-in GCP, AWS AKIA, and AWS ASIA patterns SHOULD each declare a trailing run guard by default: all three share the same weak structural shape — a 4-byte fixed prefix followed by a single variable region with no trailing anchor — the statistically weakest shape in the built-in set against large base64 payloads (confirmed by a real-world corpus hit: a 20-byte `ASIA`-prefixed candidate occurring by chance inside base64-encoded PNG image data). When a pattern declares this guard, its guard charset MUST be declared explicitly as `base64_any` — not inferred: the blobs that produce these false positives are standard-alphabet base64, a strict superset of each pattern's match charset (`url_safe_base64` for GCP, `uppercase_alphanumeric` for AKIA/ASIA), and an inferred guard charset provides no effective suppression against them (see §Trailing Run Guard, Charset resolution). Each pattern's match charset itself is unchanged; detection precision for genuine keys is unaffected. Other built-in patterns need no guard; their longer prefixes and/or dual anchors make accidental structural matches negligible.

Each built-in pattern constructor generates a new Pattern with an ephemeral random salt. For stable fakes across process restarts, load patterns from a patterns file.

## Registration

Registration is a distinct, preparatory operation that precedes the swap→restore cycle. It takes a secret value and optional registration options, infers or accepts a segment structure, and returns either a Pattern on success or an error on failure. The secret is consumed during registration and immediately discarded; the registration operation MUST NOT store the original secret anywhere.

The inferred segment structure for a registered secret is:

```
[Opaque { value: secret[..anchor_len], charset: detect(secret[..anchor_len]) },
 Variable { charset: effective_charset, min: middle_len, max: middle_len }]
```

where `anchor_len` is the number of leading secret bytes used as the detection anchor (registration option, default 3), `middle_len = secret.len() - anchor_len`, and `effective_charset` is the wide charset by default or the detected charset when `restrict-charset` is enabled. The variable portion is the region after the anchor bytes; its byte count is the variable portion for entropy assessment.

If a non-zero tail anchor length is specified (default 0), the last `tail_anchor_len` bytes of the secret are also stored as an additional trailing `opaque` segment for secondary pre-filtering:

```
[Opaque { value: secret[..anchor_len], charset: detect(...) },
 Variable { charset: ..., min: middle_len, max: middle_len },
 Opaque { value: secret[len-tail_anchor_len..], charset: detect(...) }]
```

The HMAC digest is computed as `HMAC(salt, full_secret)` where `salt` is a fresh random 32-byte value unique to this registration. The digest is stored in the Pattern's `digests` list alongside the salt.

### Entropy Requirements

The variable portion is the subsequence of secret bytes that are neither part of the anchor segments. Registration MUST fail with an `InsufficientEntropy` error (overridable with `--force` in the CLI) when the variable portion's effective entropy falls below **83 bits** — the equivalent of 14 alphanumeric bytes, the worst-case charset. Registration MUST emit a warning-level diagnostic when the effective entropy falls below **131 bits** — the equivalent of 22 alphanumeric bytes, the NIST SP 800-63B recommended minimum for machine-generated credentials.

Effective entropy is computed as:

```
entropy_bits = variable_len × log₂(charset_size)
```

where `charset_size` is the cardinality of the effective charset (92 for wide, 62 for alphanumeric, or the detected charset size when restrict-charset is enabled).

Registration MUST also emit a warning-level diagnostic when the secret's observed byte set is a subset of the alphanumeric character class (`[A-Za-z0-9]`) and restrict-charset is false — this combination produces a fake whose charset is visibly wider than the original's, which may be unexpected.

### Registration Options

- **anchor-len** (positive integer, default 3). Number of leading secret bytes stored as the detection anchor in the first `opaque` segment. Longer values reduce false-positive Aho-Corasick hits at the cost of more plaintext bytes stored in the patterns file. 3 bytes yields approximately 0.35 expected false AC hits per 8 KB of ASCII payload with 37 registered patterns; 4 bytes yields approximately 0.004. Registration MUST fail with `AnchorTooShort` if `anchor-len` is less than 2; a 0- or 1-byte anchor cannot pre-filter candidates reliably. Registration SHOULD emit a warning when `anchor-len` is exactly 2, as values below 3 (the default) are not recommended.

- **tail-anchor-len** (non-negative integer, default 0). Number of trailing secret bytes stored as a secondary detection anchor in a trailing `opaque` segment. The default of 0 is recommended: with a 3-byte leading anchor the AC filter is already tight, adding a tail anchor does not improve filtering and leaks additional secret bytes.

- **restrict-charset** (boolean, default false). When false, the variable segment's fake bytes are drawn from the wide charset. When true, fake bytes are drawn from the charset detected in the secret's variable bytes. Use restrict-charset only when the target system rejects structurally implausible replacements.

- **trailing-run-guard** (positive integer, optional, absent by default). When present, the produced Pattern declares a trailing run guard with this byte-count threshold (see §Trailing Run Guard); unless trailing-run-guard-charset is also supplied, the guard charset is the Pattern's single `variable` segment's charset — the effective charset selected by restrict-charset. Registration MUST fail with a clear error if the value is zero. The load-time no-variable-segment rejection cannot occur here: registration always produces exactly one `variable` segment, failing earlier with the 'no variable bytes' error when the anchors consume the entire secret. Absent is the recommended default: registered patterns are HMAC-gated, so accidental structural matches are already passed through unchanged, and a guard can only suppress genuine occurrences of the secret that run directly into at least the threshold count of guard-charset bytes. Declare it only when that suppression is intended — for example, to keep guard configuration consistent across structurally overlapping patterns (see §Trailing Run Guard, Selection order). Registration SHOULD emit a warning when the supplied threshold exceeds 20,000 bytes: real-world encoded blobs motivating this feature run from tens of KB to a few MB, and a threshold much larger than that range does not improve suppression coverage — a false-positive match near the end of a blob has a bounded remaining run regardless of threshold, so raising the threshold past the point where the blob typically ends only makes suppression fire less often, not more.

- **trailing-run-guard-charset** (charset name, optional, absent by default). When present, the produced Pattern declares this charset as its explicit guard charset (see §Trailing Run Guard, Charset resolution) instead of inheriting the `variable` segment's charset. The value MUST be a valid charset name; an unrecognised name MUST fail with a clear error. Supplying this option without trailing-run-guard MUST fail with a clear error — a guard charset without a guard threshold is meaningless. Exposed as the CLI `register --trailing-run-guard-charset <name>` flag (see §CLI, `register`) as well as the library registration API and direct patterns-file editing.

- **group** (string, optional). Add the new digest to an existing Pattern entry identified by this label rather than creating a new entry. All group members share the same salt; the HMAC digest is computed with the existing entry's salt.

- **force** (boolean, default false). Suppress the `InsufficientEntropy` hard failure; the entropy warning is still emitted.

Registration MUST fail with a 'no variable bytes' error if the variable portion (after anchor bytes) is empty. Registration MUST fail with a 'secret too short' error if the secret is shorter than `anchor_len`. If fake generation exhausts the collision-avoidance retry limit, registration MUST fail with a 'collision limit' error. Registration MUST NOT panic on any input.

## Patterns File

A **patterns file** is a TOML document that carries all data needed to reconstruct Pattern values across process restarts.

### Format (version 3)

The file begins with a version field:

```toml
version = 3
```

The library MUST reject any version other than 3 with a clear error message.

All patterns are stored in a single `[[pattern]]` array. Each table has:

- `identifier` (string, required): a unique human-readable name for the pattern.
- `salt` (string, required): the 32-byte pattern salt encoded as 64 lowercase hex characters. Used for both HMAC digest computation (when `digests` is non-empty) and fake derivation.
- `digests` (array of strings, optional, default `[]`): HMAC-SHA256 digests encoded as 64 lowercase hex characters. Empty array or absent means the pattern is a family pattern (no HMAC gate). Non-empty means the pattern is an instance/group pattern — detection requires `HMAC(salt, candidate)` to match one of the listed digests.
- `trailing_run_guard` (positive integer, optional): minimum trailing same-charset run length, in bytes, that suppresses a match (see §Trailing Run Guard). When present and `trailing_run_guard_charset` is absent, the pattern MUST contain at least one `variable` segment and the guard charset is the last `variable` segment's charset. A value of zero MUST be rejected at load time with a clear error. Absent means no guard — unconditional detection.
- `trailing_run_guard_charset` (string, optional): explicit guard charset name; any valid charset name is accepted (see below). When present, the guard probe uses this charset in place of the inferred one, and the pattern is not required to contain a `variable` segment. Present without `trailing_run_guard`, it MUST be rejected at load time with a clear error.
- `[[pattern.segments]]` (array of tables, required): the ordered segment sequence.

Each segment table has a `type` field (`"literal"`, `"opaque"`, or `"variable"`) and type-specific fields:

```toml
# Literal segment — verbatim in detection and fake
{ type = "literal", value = "<utf-8 string>" }

# Opaque segment — exact detection, charset-derived in fake
{ type = "opaque", value = "<utf-8 string>", charset = "<name>" }
# charset is optional; default is the minimal charset detected from value bytes.

# Variable segment — charset-constrained, derived in fake
{ type = "variable", charset = "<name>", min = <n>, max = <n> }
```

Valid charset names: `alphanumeric`, `url_safe_base64`, `base64_any`, `uppercase_alphanumeric`, `digits`, `hex_lower`, `wide`. `base64_any` is the 67-character union of the standard and URL-safe base64 alphabets plus padding — `A`–`Z`, `a`–`z`, `0`–`9`, `+`, `/`, `-`, `_`, `=` _(domain constraint: the RFC 4648 §4 and §5 alphabets)_ — and is a general-purpose charset, valid wherever a charset name is accepted: `variable` and `opaque` segments as well as `trailing_run_guard_charset`. All segment `value` fields MUST be valid UTF-8; the library MUST reject patterns with non-UTF-8 segment values.

### Example: built-in family pattern

```toml
[[pattern]]
identifier = "anthropic"
salt = "eb1f555ac9f9cbae02f88bf01a0eacdf7102a26f0f1c8987bbe32ebe45335c5b"

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
```

### Example: user-defined family pattern

```toml
[[pattern]]
identifier = "my-org-keys"
salt = "..."

[[pattern.segments]]
type = "opaque"
value = "sec_"
charset = "alphanumeric"

[[pattern.segments]]
type = "variable"
charset = "alphanumeric"
min = 20
max = 20
```

### Example: instance/group pattern

```toml
[[pattern]]
identifier = "prod-credentials"
salt = "..."
digests = [
  "5b233f88848ba55705fd68c4f5198c0eedcbe09cd72068bb5008534633c3ec4a",
  "10f3d02293e11b6bea36cb4cdde05848de63b4fd137a15e7b80c163825abcef4",
]

[[pattern.segments]]
type = "opaque"
value = "A9i"

[[pattern.segments]]
type = "variable"
charset = "wide"
min = 37
max = 37
```

### File Handling

The patterns file MUST be treated with the same sensitivity as the secrets it detects — it contains detection anchors that serve as a detection oracle for registered secrets. On Unix systems, the file SHOULD be written with mode 0600; the CLI `init`, `register`, and `define` commands MUST enforce this. The library provides serialization/deserialization functions operating on byte buffers; filesystem operations are the caller's responsibility.

## Security Properties

**Entries alone do not leak plaintext secret bytes (confidentiality).** Each entry contains only ciphertext and the fake bytes. Without the session key, the ciphertext is opaque.

**Entries are integrity-protected (fake binding).** The AEAD tag covers the fake field as associated data (AAD). Replacing an entry's fake field after `swap` produces a tag mismatch at `restore` time; no plaintext is emitted. An attacker who can write the entries file but not the session key cannot redirect decryption to an arbitrary trigger.

**Swapped payload alone does not leak secrets.** The swapped output contains only structurally-equivalent fakes. There are no tokens, markers, indices, or side-channels in the swapped payload that reference the original bytes.

**Session key is the trust gate.** The session key is generated fresh at the start of each `swap` call. It lives in process memory only, for the duration of one swap/restore cycle. It MUST NOT be written to disk. It MUST NOT appear in logs or any serialized form.

**Per-entry AEAD encryption.** Each substitution entry is independently encrypted with its own AEAD tag under the session key. `restore` decrypts entries one by one as their corresponding fakes are matched in the response stream — it does NOT decrypt the entire entries set upfront. The AEAD construction provides both confidentiality and ciphertext integrity in a single pass. Restored plaintext MUST NOT be emitted before the AEAD tag of the matching entry passes verification. A tag failure MUST produce an error; the stream MUST NOT continue.

**Literal segment bytes are visible in the fake by design.** Literal segments reproduce their bytes verbatim in every fake; this enables structural plausibility (an Anthropic fake begins with `sk-ant-api03-` so the upstream API treats it as a structurally valid key). The literal bytes carry no information about the variable portion of the secret.

**Opaque segment bytes do not appear in the fake.** Opaque segments serve as detection anchors only. Their bytes are stored in the patterns file (not the entries file) and are visible to anyone who reads the patterns file. They are derived anew in fake generation; the external system sees derived bytes, not the original anchor bytes.

**Detection anchors are confined to the patterns file.** The leading bytes of registered secrets (stored in `opaque` segment values) live in the patterns file and never appear in the entries file. The patterns file should be treated with the same sensitivity as the secrets it detects.

**Instance pattern HMAC gate prevents false swaps.** A candidate that passes segment matching but fails HMAC verification is passed through unchanged. The HMAC is computed with the Pattern's salt; the digest is stored in the patterns file. An attacker cannot forge a match without knowing the preimage of a stored digest under the specific salt.

**Shared salt within a group is safe.** All digests within a single instance/group Pattern share one salt. Distinct secrets produce distinct digests under the same salt (HMAC collision resistance). Knowing one group member's secret and its digest does not help recover any other member's secret.

## Streaming Invariants

`restore` operates on a stream of byte chunks. At any point during processing, the maximum number of bytes held without being emitted is bounded by the length of the longest fake across all entries:

```
max_hold = max { |fake_i| : fake_i ∈ entries }
```

This bound MUST hold regardless of stream length, chunk count, or chunk size. For typical secret classes this is on the order of 100–200 bytes.

Bytes that leave the window without matching any fake are emitted immediately. A fake whose bytes are split across a chunk boundary MUST still be found and restored correctly.

When no fake from the entries appears anywhere in the response, the stream MUST be forwarded byte-for-byte unchanged. `restore` MUST NOT produce an error in this case.

## Fake Generation

All fakes MUST satisfy:

- **Same length:** the fake has the same total byte count as the original secret.
- **No collision with original:** if the derived fake equals the original secret, the implementation MUST increment the derivation counter and re-derive. In practice this case is unreachable given cryptographic hash properties; the counter mechanism provides a deterministic fallback guarantee.

**Fake generation by segment type:**

- **`literal` segment:** the fake bytes at these positions are the segment's fixed value, reproduced verbatim.
- **`opaque` segment:** the fake bytes at these positions are derived deterministically from the Pattern's salt, the full matched candidate bytes, and the segment's charset. They are never equal to the original anchor bytes (ensured by the no-collision guarantee over the full fake).
- **`variable` segment:** the fake bytes at these positions are derived deterministically from the Pattern's salt and drawn from the segment's charset. The count equals the number of bytes consumed during detection.

All derived bytes (opaque and variable segments) are produced by seeding a PRNG from `HMAC(salt, candidate || counter)` and drawing bytes from the respective charset. The counter starts at zero and increments only if the full fake equals the original.

**Stability:** every detection of the same secret under the same Pattern MUST produce the same fake. Deterministic derivation ensures this without caching — re-derivation at each detection is equivalent.

## CLI Contract

The CLI exposes `swap`, `restore`, `init`, `register`, `define`, `list`, `inspect`, and `remove` at the process boundary.

**`swap`:** reads the complete payload from stdin; writes the swapped payload to stdout; writes the entries to a caller-specified path; writes the session key to a caller-specified path. The session key output file MUST be created with mode 0600. No other file permission is acceptable. The `swap` subcommand MUST accept a `--patterns <FILE>` argument specifying the patterns file; this argument is required.

**`restore`:** reads the response stream from stdin incrementally and writes output to stdout as each chunk resolves. It MUST NOT buffer stdin to completion before writing to stdout. The session key MUST be supplied via the `DOPPEL_KEY` environment variable. A `--key` command-line flag MUST NOT exist. _(Domain constraint: command-line arguments are visible in process listings, `/proc`, and shell history.)_

**`init`:** creates a new TOML patterns file (version 3) at the caller-specified path. The file includes all built-in family pattern definitions with freshly generated stable salts and an empty `digests` list; the file is self-describing and directly editable. The command MUST fail if the file already exists unless `--force` is specified. When `--force` is used, all salts are regenerated — existing fakes produced from the old salts become invalid. The patterns file MUST be written with mode 0600 on Unix.

**`register`:** reads a secret value from stdin (raw bytes, no trimming), loads the patterns file, registers the secret as an instance pattern, appends the new entry (or extends an existing group entry with `--group <identifier>`), and writes the file back. Options: `--identifier <id>` (required for new entries), `--anchor-len <n>` (default 3), `--tail-anchor-len <n>` (default 0), `--restrict-charset` (default false), `--trailing-run-guard <n>` (optional, absent by default), `--trailing-run-guard-charset <name>` (optional, requires `--trailing-run-guard`; one of the recognised charset names including `base64_any`), `--group <identifier>` (add to existing group), `--force` (suppress entropy failure). The secret MUST NOT appear in command-line arguments. Existing comments in the patterns file MUST be preserved. `--trailing-run-guard` and `--trailing-run-guard-charset` MUST both be rejected together with `--group`: guard configuration lives on the pattern entry, and has no effect when only appending a digest to an existing group member. `--trailing-run-guard-charset` without `--trailing-run-guard` MUST be rejected with a clear error. `--trailing-run-guard-charset` naming an unrecognised charset MUST be rejected with a clear error.

**`define`:** adds a user-defined family pattern to the patterns file. The caller supplies an identifier, one or more segment specifications, and the patterns file path. A fresh stable salt is generated. `define` MUST fail if the identifier already exists. `define` MUST fail if the segment list is empty, if any segment specifies an unrecognised charset name, if any `variable` segment has `min > max`, if the first segment is not a `literal` or `opaque` segment, if the segment list contains no `variable` segment, or if the first segment's value is shorter than 2 bytes. `define` SHOULD emit a warning when the first segment value is shorter than 4 bytes, as a short anchor generates many false Aho-Corasick hits. The patterns file MUST be written back atomically with mode 0600.

**`list`:** reads the patterns file and writes a human-readable summary to stdout: each pattern entry with its identifier, segment description, digest count, and charset summary. When an entry declares a trailing run guard, `list` MUST also display its threshold and effective guard charset (the explicit `trailing_run_guard_charset` if set, otherwise the charset the guard infers per item 45); entries with no guard show no guard information. `list` MUST NOT modify the patterns file.

**`inspect`:** reads the patterns file and writes full detail for a single pattern to stdout, located by identifier. Outputs all segments, digest count, entropy estimate for variable portions, the salt fingerprint (first 8 hex characters only), and the trailing run guard configuration (threshold and effective charset, or an explicit indication that no guard is declared). `inspect` MUST NOT modify the patterns file.

**`remove`:** removes a pattern from the patterns file by identifier and writes the updated file back atomically with mode 0600. `remove` MUST fail if the identifier is not found. `remove` MUST emit a warning to stderr (but MUST NOT fail) when the target identifier matches a built-in family pattern. Existing comments in the patterns file MUST be preserved.

## Behavioral Invariants

1. `swap` MUST replace every secret detected by the supplied Patterns with a structurally-equivalent fake.
2. `swap` MUST NOT modify bytes that are not identified as secrets by the supplied Patterns.
3. `swap` MUST return entries containing exactly one record per distinct secret substituted in that call, and no records for secrets not substituted.
4. `restore` MUST restore every fake present in the response stream to its original bytes, regardless of where chunk boundaries fall.
5. `restore` MUST NOT emit restored plaintext before the AEAD tag of the corresponding entry has been verified.
6. An AEAD tag failure MUST produce an error; the stream MUST NOT continue with a raw fake or any partially-decrypted content in its place.
7. `restore` MUST forward all bytes unchanged when no fake from the entries appears in the stream; it MUST NOT produce an error in this case.
8. `restore` MUST NOT hold more than `max { |fake_i| : fake_i ∈ entries }` bytes unemitted at any point during processing.
9. The entries MUST NOT contain plaintext bytes from any secret's variable or opaque portions in any field or serialized form. The session key MUST NOT be serialized together with or embedded within the entries.
10. The session key MUST NOT be written to disk, appear in logs, or be included in any serialized form.
11. The session key MUST NOT be retained after the swap/restore cycle ends. The entries MUST NOT be retained after the swap/restore cycle ends.
12. All key material MUST be destroyed (overwritten with zeros or equivalent) when the swap/restore cycle ends.
13. The same secret detected under the same Pattern MUST produce the same fake. Stability applies to all Pattern types.
14. Multiple occurrences of the same secret within a single `swap` call each produce the same fake in the swapped output; all occurrences share a single entry.
15. A fake MUST NOT equal the original secret; if derivation at counter zero produces a fake equal to the original, the implementation MUST increment the counter and re-derive. If all attempts produce a collision, the operation MUST fail with an error rather than emitting the original as a fake.
16. An instance/group pattern candidate that passes segment matching but fails HMAC verification against all digests MUST be passed through unchanged; no replacement occurs.
17. Each Pattern MUST use a unique salt; salt reuse across distinct Pattern entries is prohibited. Digests within the same Pattern entry share one salt by design.
18. Detection MUST produce leftmost-longest matches; overlapping matches MUST NOT be produced. When two Patterns both match at the same byte position with the same byte length, the Pattern whose first segment is `literal` takes precedence over the Pattern whose first segment is `opaque`. When two Patterns remain tied after both rules (same match-end position, same first-segment kind), the Pattern that declares a trailing run guard MUST take precedence over the Pattern that does not; when both tied Patterns declare a trailing run guard, the Pattern with the larger threshold MUST take precedence. These two guard tie-breaks apply strictly after, and MUST NOT override, the longest-match and literal-first rules.
19. `restore` MUST perform only exact matching against fake byte strings from the entries; it MUST NOT run pattern detection of any kind.
20. The CLI `restore` command MUST accept the session key only via the `DOPPEL_KEY` environment variable; no other delivery mechanism is provided or accepted.
21. The CLI `swap` command MUST create the session key output file with permission mode 0600.
22. The built-in family pattern set MUST cover Anthropic, OpenAI, AWS IAM, GitHub PATs, and GCP API keys at minimum.
23. `swap` called on a payload containing no detectable secrets MUST return the payload bytes unchanged and an empty entries set.
24. The AEAD tag for each entry MUST cover the entry's fake field as associated data (AAD). Replacing an entry's fake field after encryption MUST cause `restore` to return an error.
25. `register` MUST fail with `InsufficientEntropy` when the variable portion's effective entropy is below 83 bits and `--force` is not specified. `register` MUST emit a warning when effective entropy is below 131 bits.
26. `register` MUST emit a warning-level diagnostic when the secret's observed byte set is a subset of the alphanumeric character class and restrict-charset is false.
27. Every `literal` segment in a matched Pattern MUST appear verbatim at the corresponding byte positions of the fake.
28. Every `opaque` segment in a matched Pattern MUST produce derived bytes (drawn from the segment's charset via HMAC-seeded PRNG) at the corresponding byte positions of the fake. The original opaque segment value MUST NOT appear verbatim in the fake.
29. Every `variable` segment in a fake MUST contain only bytes drawn from that segment's charset.
30. The first segment of every Pattern MUST be a `literal` or `opaque` segment. `define` and `register` MUST reject patterns whose first segment is `variable`.
31. When a Pattern's `digests` list is non-empty, all `variable` segments in that Pattern MUST have `min == max`. A variable-length instance pattern has no defined candidate length for HMAC computation.
32. A user-defined pattern identifier MUST be unique within the patterns file; `define` and `register` (for new entries) MUST fail if the identifier already exists.
33. Removing a built-in family pattern identifier from the patterns file is permitted; `swap` will not apply that pattern class when the identifier is absent.
34. The patterns file version MUST be 3; the library MUST reject any file whose version field is not 3.
35. `list` and `inspect` MUST NOT modify the patterns file.
36. `remove` MUST write the updated patterns file atomically; no partial write MUST be observable by concurrent readers.
37. The `register`, `define`, and `remove` commands MUST preserve all comments present in the patterns file when writing it back.
38. The CLI `swap` command MUST successfully create the session key output file before writing any bytes to stdout or the entries file; if key file creation fails, no output MUST be produced.
39. `Detector::swap` called on the same payload with the same Patterns MUST produce fakes identical to those produced by the free `swap` function. "Same Patterns" means the same Pattern values including their salts — not merely the same pattern class.
40. `Detector` MUST implement `Send + Sync`. It MUST be safe to share a `Detector` across threads without external synchronization.
41. The Aho-Corasick automaton MUST NOT be rebuilt on `Detector::swap` calls. The automaton is built exactly once in `Detector::new`.
42. `register` MUST fail with `AnchorTooShort` when `anchor_len` is 0 or 1. `register` SHOULD emit a warning when `anchor_len` is 2. The default of 3 is the minimum recommended value.
43. `define` MUST fail when the first segment value is shorter than 2 bytes. `define` SHOULD emit a warning when the first segment value is shorter than 4 bytes.
44. A Pattern MAY declare a trailing run guard: a positive minimum trailing same-charset run length in bytes. When at least that many consecutive bytes immediately following a winning match all belong to the guard charset, the match MUST be discarded and the position MUST yield no detection. When end of payload or a byte outside the guard charset is reached before the threshold count is accumulated, the match MUST stand.
45. When a pattern declares a trailing run guard without an explicit guard charset, the guard charset MUST be the charset of the pattern's last `variable` segment; a pattern that declares a trailing run guard with no explicit guard charset and no `variable` segment MUST be rejected at patterns-file load time with a clear error. A declared trailing run guard threshold MUST be positive; a threshold of zero MUST be rejected at load and registration time.
46. Trailing-run-guard suppression applies only to the single winning match selected per item 18's leftmost-longest rule. Competing structural matches at the same starting position MUST NOT be re-evaluated after suppression; the position yields no detection.
47. Trailing-run-guard evaluation for one pattern MUST NOT depend on any other pattern's configuration, nor on any match or suppression decision at any other position. The trailing probe MUST examine bytes only for guard-charset membership, forward from the match end, and MUST NOT examine bytes preceding the match start.
48. A pattern that declares no trailing run guard MUST retain unconditional detection semantics: its matches MUST NOT be suppressed by any trailing-context examination.
49. Registration MUST accept an optional trailing-run-guard threshold option and an optional explicit guard-charset option. When the threshold is supplied and positive, the produced Pattern MUST declare a trailing run guard with that threshold, its charset being the Pattern's `variable` segment charset unless the explicit guard-charset option is supplied, in which case the declared charset MUST be used (item 51). When the threshold is supplied as zero, registration MUST fail with a clear error. The no-variable-segment rejection of item 45 is unreachable through registration: every registered secret's Pattern contains exactly one `variable` segment by construction.
50. `register` SHOULD emit a warning when a supplied trailing-run-guard threshold exceeds 20,000 bytes. Patterns-file load SHOULD emit the same warning when a loaded pattern's `trailing_run_guard` field exceeds 20,000 bytes. This is advisory only: a threshold above 20,000 MUST NOT be rejected.
51. A pattern MAY declare an explicit guard charset alongside its trailing run guard. When declared, the trailing probe MUST test bytes for membership in exactly the declared charset, regardless of any segment's charset. A pattern that declares both a trailing run guard and an explicit guard charset MUST be accepted at load time even when it contains no `variable` segment. An explicit guard charset declared without a trailing run guard threshold MUST be rejected at load and registration time with a clear error. When no explicit guard charset is declared, guard behavior MUST be identical to the inferred-charset behavior of item 45. This relaxation of the `variable`-segment requirement applies only to guard-charset inference: a Pattern with no `opaque` or `variable` segment has no basis for fake derivation, so item 15's collision-avoidance requirement still applies — such a Pattern is loadable but its match can never be swapped without triggering that failure.

## Verifiable Conditions

1. Given a payload containing a secret matching a family pattern, the swapped output contains no byte subsequence equal to the original secret.
2. Given a swapped payload, the corresponding entries, and the session key, passing the swapped payload through `restore` produces bytes that exactly equal the original payload.
3. Two `swap` calls on the same secret under the same Pattern produce identical fake bytes in the output.
4. Given a response where a fake straddles a chunk boundary, `restore` restores the original secret correctly.
5. Given a response that contains no fake from the entries, `restore` produces output byte-for-byte identical to the input and returns no error.
6. Given an entries set where one entry's AEAD tag has been tampered with, `restore` returns an error and emits no partially-restored output.
7. The entries produced by `swap` contain no byte sequence from the variable or opaque portions of any detected secret, regardless of serialization.
8. The session key file created by the CLI `swap` command has permission mode 0600.
9. The CLI `restore` command begins writing to stdout before stdin reaches EOF when the input is a streaming byte source.
10. Multiple occurrences of the same secret within a single payload each produce the same fake bytes in the swapped output.
11. A candidate that shares an opaque segment's bytes and exact length with a registered secret but does not match any HMAC digest passes through the swapped payload unchanged.
12. Given an empty set of patterns, `swap` returns the payload unchanged and an empty entries set.
13. Given a secret whose pattern contains a trailing `literal` segment (e.g., a fixed suffix or an embedded marker), the fake produced by `swap` reproduces that literal segment verbatim at the correct byte position.
14. A family pattern defined with `[opaque("sec_"), variable(alphanumeric, 20, 20)]` detects and replaces a payload containing `sec_` followed by exactly 20 alphanumeric characters such that the fake begins with 4 derived bytes (not `sec_`) and the variable portion differs from the original.
15. `list` output contains the identifier of every pattern entry present in the patterns file.
16. After `remove` succeeds on an existing identifier, the resulting patterns file MUST NOT contain any entry with that identifier.
17. Given a group pattern with two digests for secrets A and B sharing salt S, `swap` correctly detects and replaces both A and B, producing distinct fakes, using a single HMAC computation per candidate position.
18. Given a guarded pattern's structural match immediately followed by at least the threshold count of guard-charset bytes, `swap` returns that region of the payload unchanged and produces no entry for it.
19. Given a guarded pattern's structural match followed by fewer than the threshold count of guard-charset bytes (terminated by a non-charset byte or end of payload), `swap` replaces the match normally.
20. Given a payload where a guard-suppressed match is followed within the probe window by a different pattern's genuine secret, that secret is detected and replaced normally at its own position.
21. Loading a patterns file in which a pattern declares a trailing run guard with no explicit guard charset and no `variable` segment fails with a clear error; the same pattern with an explicit guard charset declared loads successfully.
22. Registering a secret with a positive trailing-run-guard threshold yields a Pattern under which `swap` suppresses the secret when it is directly followed by at least the threshold count of guard-charset bytes, and replaces it normally when it is followed by a non-charset byte or end of payload.
23. Registering a secret with a trailing-run-guard threshold of zero fails with a clear error; loading a patterns file whose `trailing_run_guard` field is zero fails with a clear error.
24. Given two Patterns whose segment structures both accept the same candidate at the same position with equal match length and the same first-segment kind, exactly one of which declares a trailing run guard, `swap` replaces the candidate with the fake derived from the guarded Pattern's salt.
25. Given two Patterns tied as in condition 24 where both declare a trailing run guard with different thresholds, `swap` replaces the candidate with the fake derived from the larger-threshold Pattern's salt; when the trailing context satisfies the smaller threshold but not the larger, the match stands and is replaced rather than suppressed.
26. Given a pattern whose explicit guard charset differs from its last `variable` segment's charset, suppression is decided by membership in the declared guard charset: a trailing run that meets the threshold under the declared charset suppresses the match even when bytes in that run fall outside the segment charset, and a trailing run that fails to meet the threshold under the declared charset leaves the match standing even when it would meet the threshold under the segment charset.
27. Given the built-in GCP, AWS AKIA, or AWS ASIA pattern at its default guard configuration, a structural candidate of that pattern's shape embedded in unwrapped standard-alphabet base64 data and followed by at least the default threshold count of standard-base64 bytes is suppressed and produces no entry.
28. Loading a patterns file in which a pattern declares `trailing_run_guard_charset` but no `trailing_run_guard` fails with a clear error; registering a secret with a guard-charset option but no guard threshold fails with a clear error.

## Known Limitations / Accepted Trade-offs

- **Coverage of transformed secrets.** Detection is exact and deterministic for any byte sequence matching a declared pattern. Coverage is limited in the sense that secrets split across positions, base64-encoded, obfuscated, or otherwise transformed before the payload is formed are not matched.
- **Opaque segment bytes in patterns file.** Reliable detection of unstructured secrets requires storing enough of the secret to anchor detection. The leading bytes of registered secrets (stored in `opaque` segment values, default 3 bytes) are plaintext in the patterns file. Callers who persist pattern files should treat them with the same sensitivity as the secrets they detect.
- **Cross-request correlation.** Because fakes are stable for the lifetime of a Pattern, an observer with access to multiple swapped payloads can correlate any two payloads that used the same Pattern — they will share the same fake. This is the accepted cost of fake stability.
- **Body bytes only.** Header inspection is out of scope.
- **Compressed and binary payloads.** Matching operates on raw bytes. Payloads that are compressed, encrypted, or encoded before reaching this library are not covered.
- **Single-cycle entries.** The entries and session key are designed for exactly one swap/restore cycle. They are not sharable across processes and are not valid after the cycle ends.
- **Session key file deletion is caller responsibility.** The CLI `restore` command receives the session key value via environment variable but has no specified mechanism to locate the key file.
- **Pre-Aug-2024 OpenAI project key format not detected.** The original `sk-proj-` format (56 chars total, no embedded `T3BlbkFJ` marker) is not matched. These keys required only `sk-proj-<48 url_safe_b64>` — structurally indistinguishable from arbitrary base64 without the marker.
- **Trailing run guard accepts a bounded false-negative class.** A guarded pattern will not detect a genuine secret that is immediately followed, with no intervening non-charset byte, by at least the threshold count of guard-charset bytes — i.e., a secret concatenated directly into a large same-charset blob. This is deliberate: such placement is adjacent to the transformed-secret forms already declared out of scope, and the alternative (routine corruption of large encoded payloads by false replacements) is worse. Pattern authors choose the threshold to bound this class.
- **Trailing run guard is forward-only.** Bytes preceding a match are never probed. This is a deliberate scope choice, not an oversight: the detection engine's matching model is forward-consuming throughout, and a backward probe would examine bytes the scan has already resolved. The accepted coverage gap is small — under an idealized i.i.d.-uniform-symbol model of base64 data, an accidental match lands within the final threshold-sized tail of a blob (where the forward probe cannot accumulate the threshold) in roughly threshold/blob-size of cases, e.g. on the order of 0.1% for a low-kilobyte threshold against a multi-megabyte blob. Order-of-magnitude estimate, not a measured rate.
- **A larger threshold is not uniformly better.** Because suppression requires accumulating the full threshold count of guard-charset bytes before end of payload, a match near the tail of a blob shorter than the threshold can never be suppressed, however large the threshold. Increasing the threshold trades reduced coverage of end-of-blob false positives for a (small) reduction in the false-negative class described above; it does not monotonically improve suppression. This was confirmed empirically against real screenshot corpora: raising the threshold from 1,024 to 65,536 bytes measurably increased, rather than decreased, the number of unsuppressed false positives. This is the rationale for the item 50 warning at 20,000 bytes — well past the point where real-world blob sizes make this trade-off unfavorable.
- **The guard does not distinguish filler from adjacent secrets.** The trailing probe checks charset membership only; it cannot tell meaningless high-entropy filler from another genuine secret that happens to share the guard charset. A real secret trailing a suppressed match still gets detected independently at its own position, so this imprecision affects only the quality of the suppression heuristic, never the detection of other secrets.
- **Uneven guard configuration across overlapping patterns is a pattern-authoring responsibility.** When two structurally overlapping patterns coexist and only the longer one declares a guard, a suppressed long match does not cascade to the shorter unguarded pattern at the same position (see §Trailing Run Guard, Selection order). Guarding the stronger pattern while leaving a weaker overlapping one unguarded is an inconsistent configuration, not a defect in the mechanism; the unguarded pattern's own detections elsewhere are unaffected.
- **Line-wrapped and MIME-style base64 defeats the guard.** Encoders that insert line breaks into base64 output (classically CRLF every 76 characters, as in MIME) interrupt any charset-membership run well before a useful threshold accumulates, so trailing-run-guard suppression cannot fire against such blobs regardless of threshold or guard charset choice. This gap is accepted: the payload class the guard targets — JSON and data-URI embeddings of encoded binary — carries unwrapped, continuous base64 in practice. Widening the guard charset to include line-break bytes would not be a fix; it moves the charset toward `wide` and enlarges the over-suppression false-negative class described above.
