# its-classified — Specification

> Key words MUST, SHOULD, SHOULD NOT, MAY are used per RFC 2119.

## Purpose

`its-classified` is a Rust library that scrubs secrets from arbitrary byte
payloads before they are forwarded to external services, then transparently
restores them in the corresponding response — including streaming (SSE)
responses.

The primary threat it addresses is **accidental secret exfiltration**: secrets
that end up in LLM request bodies through normal development work (tool output,
file contents, environment variables, debug context). It is not a DLP system and
does not guarantee complete coverage. It guarantees that what it does scrub is
handled correctly and transparently.

### Scope

- **In scope:** request and response body bytes. Headers are out of scope.
- **Deployment context:** local developer machine. The caller generally trusts
  the machine; the goal is to avoid exfiltrating secrets to external providers,
  not to harden against a compromised host.
- **Best-effort detection:** the library catches high-confidence matches.
  Obfuscated, split, or encoded secrets are explicitly out of scope. Detection
  that requires false positive–prone heuristics (e.g. pure entropy scoring) is
  excluded by default.

### Non-goals

- Detecting secrets that are deliberately obfuscated or escaped.
- System-wide interception (TLS MITM, iptables redirect).
- PII detection or GDPR compliance.
- Persistent secret storage of any kind.
- Guaranteed 100% coverage — best-effort is the contract.

---

## Core API

```rust
/// Scrub secrets from a payload.
///
/// Detects all secrets matching `patterns` in `payload`, replaces each with a
/// structurally-equivalent fake, and returns the scrubbed payload together with
/// an opaque handle that can restore the originals.
///
/// The returned `ScrubHandle` is ephemeral: it is valid for the duration of one
/// request/response cycle and MUST be dropped immediately after `unscrub`
/// completes.
pub fn scrub(
    payload: &[u8],
    patterns: &[Pattern],
) -> (Vec<u8>, ScrubHandle);

/// Restore scrubbed secrets in a response stream.
///
/// Scans each chunk of `response` for fakes produced by a prior `scrub` call
/// on the same `handle`, replaces them with the original secrets, and forwards
/// the corrected chunks downstream.
///
/// Works correctly over streaming responses (SSE, chunked transfer): chunks are
/// held only as long as needed to resolve an ambiguous match at a chunk
/// boundary. The maximum hold depth is bounded by the longest secret length
/// across all active patterns.
///
/// If a fake does not appear in the response the chunk is forwarded unchanged.
/// `unscrub` MUST NOT corrupt output when a fake is absent.
pub fn unscrub(
    response: impl Stream<Item = Bytes>,
    handle: ScrubHandle,
    patterns: &[Pattern],
) -> impl Stream<Item = Bytes>;
```

### Why `patterns` appears in both calls

In `scrub`, patterns drive detection. In `unscrub`, patterns are needed by the
stream-aware suspicion engine: to know when to start holding chunks (a prefix
has started arriving), how many bytes to hold (the expected length of the
candidate), and when to release (match confirmed or structurally impossible).
Over a fully-buffered response the patterns are not needed for replacement, but
`unscrub` must handle streams, so they are a required input.

---

## `ScrubHandle`

`ScrubHandle` is an opaque, session-scoped encrypted blob. It MUST NOT expose
the original secrets as plaintext in any accessible field.

### Internal structure

```
session_key  = 32 random bytes, generated at scrub() time, in memory only
entry        = { fake: Vec<u8>, ciphertext: AEAD_encrypt(original, key=session_key, ad=&fake) }
ScrubHandle  = { session_key, entries: Vec<entry> }
```

The `fake` bytes are what appear in the scrubbed payload — the structural replacement
the model sees. They are also the scan target for `unscrub`: it searches each response
chunk for any `fake` from the entries and decrypts the corresponding ciphertext to
recover the original. There is no separate token or identifier embedded in the payload;
the fake is its own index.

### Security properties

- **`ScrubHandle` alone does not leak secrets.** Entries contain only
  ciphertext; decryption requires `session_key`.
- **The scrubbed payload alone does not leak secrets.** It contains only
  structurally-equivalent fakes; neither reveals the original.
- **`session_key` is the trust gate.** It lives in process memory for the
  duration of one request/response cycle, then is dropped. It is never written
  to disk, never logged.
- Secrets are only in memory for the duration of the request. After `unscrub`
  completes and `ScrubHandle` is dropped, no secret material remains.

### Lifetime guarantee

`ScrubHandle` MUST be dropped no later than when the response stream produced
by `unscrub` is exhausted or cancelled. Callers SHOULD scope it to the
request/response future.

---

## Pattern types

### Tier 1 — Known secret classes

A `Tier1Pattern` describes a class of well-known secrets by structure. Detection
is structural: a fixed prefix match followed by a charset and length scan.

```rust
pub struct Tier1Pattern {
    /// Human-readable class name, e.g. "anthropic-api-key".
    pub name: &'static str,
    /// Literal prefix that MUST appear verbatim, e.g. "sk-ant-api03-".
    pub prefix: &'static str,
    /// Valid characters for the payload portion after the prefix.
    pub charset: Charset,
    /// Inclusive length range of the full secret (prefix + payload).
    pub length: RangeInclusive<usize>,
}
```

The fake for a Tier 1 match is generated by preserving the prefix exactly and
filling the payload portion with random characters drawn from the same `charset`,
sampled from a CSPRNG. The fake has the same total length as the detected
original.

**Effect on the model:** the model receives a structurally valid-looking
credential — correct prefix, correct character set, correct length. It can
reason about format ("this looks like a valid Anthropic key"), length ("your
key is the right length"), and prefix correctness, without the true secret bytes
ever leaving the machine.

The library MUST ship built-in `Tier1Pattern` definitions for at minimum:
Anthropic API keys, OpenAI API keys, AWS IAM access key IDs, GitHub personal
access tokens (classic and fine-grained), and GCP API keys. Additional patterns
MAY be added; the set is not closed.

### Tier 2 — Registered arbitrary secrets

A `Tier2Pattern` covers secrets that do not conform to any known class prefix.
The caller registers enough information to detect the secret in arbitrary text;
the full secret is never stored persistently.

```rust
pub struct Tier2Pattern {
    /// A portion of the beginning of the secret, sufficient for reliable match
    /// anchoring. Length is a caller judgment call: longer reduces false
    /// positives, shorter leaks less about the secret.
    pub start_part: Vec<u8>,
    /// A portion of the end of the secret, used for confirmation.
    pub end_part: Vec<u8>,
    /// Exact byte length of the full secret.
    pub length: usize,
    /// Valid characters for the interior of the secret. The caller SHOULD
    /// supply this rather than requiring the library to infer it, as the caller
    /// knows the secret format.
    pub charset: Charset,
    /// HMAC-SHA256(secret, salt) where `salt` is caller-supplied and stored
    /// alongside the hash. Used to confirm a candidate match before replacing.
    /// The salt MUST be unique per registration and never reused.
    pub verification: Verification,
    /// The structurally-equivalent fake to use as the replacement. Generated
    /// once at registration time using `charset` and `length`, stored here.
    /// The fake is not a secret.
    pub fake: Vec<u8>,
}

pub struct Verification {
    pub salt: [u8; 32],
    pub hmac: [u8; 32],
}
```

#### What persistent storage contains for Tier 2

A registered secret persists `start_part`, `end_part`, `length`, `charset`,
`verification`, and `fake`. **It never persists the full secret.** This is a
deliberate tradeoff: leaking `start_part` and `end_part` reduces the entropy of
the secret by a bounded, caller-controlled amount, which is the unavoidable cost
of reliable deterministic detection.

The `verification.hmac` enables confirmation of a candidate match without
storing the secret: hash the candidate with the stored salt and compare. The
`verification.salt` prevents the stored hash from being used to verify a guessed
secret without the salt (i.e., rainbow-table attacks against the registration
database are infeasible).

#### Fake stability

The fake for a Tier 2 secret is fixed at registration time and reused across
all scrub calls. This ensures cache key stability when `its-classified` is used
upstream of a caching layer: the same secret always maps to the same fake within
a registration lifetime.

---

## Detection algorithm

Both tiers share the same scanning contract: the library scans the payload
left-to-right, finding the leftmost-longest match at each position. Overlapping
matches are not produced.

**Tier 1 detection:**
1. At each byte position, test whether any `Tier1Pattern.prefix` matches.
2. On a prefix hit, verify that the following bytes satisfy `charset` for
   `length - prefix.len()` bytes.
3. On structural confirmation, extract the candidate and replace.

**Tier 2 detection:**
1. At each byte position, test whether any `Tier2Pattern.start_part` matches.
2. On a start hit, verify length and `end_part` at the expected offset.
3. Compute HMAC of the candidate; compare against `verification`. Only replace
   on HMAC match.
4. HMAC mismatch means a false structural hit; pass through unchanged.

Detection MUST handle the case where a secret spans a chunk boundary in the
input. The `scrub` function receives a complete payload (not a stream), so
boundary handling in `scrub` is not required. `unscrub` operates on a stream
and MUST handle boundaries as specified below.

---

## Streaming behavior (`unscrub`)

### Suspicion-driven buffering

`unscrub` MUST NOT buffer the entire response. It MUST use suspicion-driven
chunk holding:

1. Maintain a set of **active suspects**: byte positions in the stream where a
   known prefix (Tier 1) or `start_part` (Tier 2) has started matching but the
   full candidate has not yet arrived.
2. When a suspect is opened: hold subsequent chunks until one of:
   - The full expected `length` of bytes has arrived → run confirmation
     (structural for Tier 1, HMAC for Tier 2).
   - An incoming byte violates `charset` before `length` is reached → close
     suspect, release held chunks unmodified, continue scanning.
3. On confirmed match: replace the candidate bytes with the fake (Tier 1) or
   the registered fake (Tier 2), then release the processed chunks downstream.
4. On failed match: release held chunks unmodified.
5. Multiple suspects MAY be open simultaneously if two prefixes overlap in the
   stream.

### Buffer depth guarantee

The maximum number of bytes held at any time is bounded by:

```
max_hold = max(length) across all active patterns
```

For typical secret classes this is on the order of 100–200 bytes. This bound
MUST hold regardless of response size or chunk count.

### Replacement in the response

`unscrub` scans each chunk for the exact `fake` bytes stored in each `ScrubHandle` entry.
On a match it decrypts the corresponding ciphertext with `session_key` and restores the
original. This handles the case where the model echoes back a value that was scrubbed in
the request (e.g. a secret parroted from context into the reply).

If a fake does not appear in the response the stream is forwarded unchanged. `unscrub`
MUST NOT produce an error or corrupt the stream in this case.

---

## Fake generation

Fakes MUST satisfy:

- **Same prefix** (Tier 1): the prefix bytes are copied exactly from the
  `Tier1Pattern`.
- **Same length**: the fake has the same total byte length as the original.
- **Same charset**: every non-prefix byte of the fake is drawn from the
  pattern's `charset`.
- **Unpredictable payload**: payload bytes MUST be drawn from a CSPRNG. The
  same secret in two different `scrub` calls MUST NOT produce the same fake
  (per-call freshness). Exception: Tier 2 fakes are fixed at registration (see
  above).
- **Not equal to the original**: if the CSPRNG happens to produce the original,
  resample. This MUST be enforced.

---

## Security posture summary

| Property | Guarantee |
|---|---|
| Secrets in persistent storage | Never. Tier 2 stores only structural fingerprint + HMAC. |
| Secrets in memory | Only for the duration of one request/response cycle. |
| `ScrubHandle` leaked to disk | Ciphertext only; unreadable without `session_key`. |
| Scrubbed payload observed in transit | Contains structural fakes only. No original bytes, no separate tokens. |
| Same secret across calls | Different fakes per call (Tier 1). Same fake per registration (Tier 2). |
| Model reasoning about secret format | Preserved: fake has identical prefix, length, charset. |
| Coverage | Best-effort. Obfuscated or split secrets are out of scope. |

---

## Prior art and references

The following projects implement related ideas and are worth studying, in
particular for pattern libraries and fake generation:

- **[mirage-proxy](https://github.com/chandika/mirage-proxy)** (Rust) — the
  closest prior art. Structure-preserving plausible fakes, bidirectional,
  sub-millisecond. Ships 30+ built-in pattern classes. The pattern library
  (`src/patterns.rs`) and faker (`src/faker.rs`) are directly relevant
  references for Tier 1 built-in class definitions. Architecture differs: it
  is a standalone proxy process; `its-classified` is an in-process library with
  a stream-aware API.

- **[CloakLLM](https://github.com/cloakllm/CloakLLM)** (Python) — covers the
  SSE streaming problem with a `StreamDesanitizer` state machine that replaces
  tokens as chunks arrive without full buffering. Compliance-oriented; uses
  visible `[CATEGORY_N]` tokens rather than structure-preserving fakes.

- **[scrub-llm](https://github.com/haasonsaas/scrub-llm)** (Python) — 30+
  built-in patterns, bidirectional, lightweight. Pattern list is a useful
  reference for Tier 1 coverage completeness.

- **[ctxproxy](https://github.com/jakobhuss/ctxproxy)** (Go) — modular
  proxy server with stable placeholder tokens and transparent restoration.
  Pluggable scanner backends.

- **[Presidio](https://github.com/microsoft/presidio)** (Python) — Microsoft's
  PII detection and anonymization framework. PII-focused rather than
  credential-focused, but the detection pipeline architecture (regex → NER →
  custom) is a useful reference for building layered detection.
