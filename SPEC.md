# its-classified — Specification

> The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are used per RFC 2119.

## Purpose

`its-classified` intercepts secrets in arbitrary byte payloads before they reach an external service, replaces them with structurally-equivalent fakes, and transparently restores the originals in the corresponding response — including streaming (SSE) responses. The threat it addresses is accidental secret exfiltration: secrets that enter LLM request bodies through normal development work (tool output, file contents, environment variables, debug context). It guarantees that what it detects is handled correctly and invisibly; it makes no claim about complete coverage.

## Non-Goals

- Detecting secrets that are deliberately obfuscated, split, base64-encoded, or otherwise transformed before reaching the payload.
- System-wide network interception (TLS MITM, packet filtering, iptables redirect).
- PII detection, GDPR compliance, or any regulatory-compliance goal.
- Persistent storage of original secrets.
- Guaranteed complete coverage — best-effort detection is the explicit contract, not a limitation to be fixed.
- Header inspection; scope is request and response body bytes only.
- Multi-hop or nested scrub/unscrub chains.
- Defense against a compromised host or a malicious caller with access to process memory.

## Core Mental Model

The library's surface area is defined by three operations and three data abstractions:

**Pattern** is an opaque detection descriptor. It encapsulates everything needed to find a specific secret or secret class in an arbitrary payload and replace it with a structurally-equivalent fake: the detection mechanism, character set, and the stable fake mapping — either a pre-generated fake (Tier 2) or a per-secret fake deterministically derived from the Pattern on each detection (Tier 1). Built-in Tier 1 definitions and Tier 2 registrations both produce Patterns; `scrub` treats them identically and is not aware of tier distinctions. Built-in Tier 1 Patterns are canonical singleton values — one per class.

**`scrub`** receives a complete payload and a set of Patterns. It scans for secrets left-to-right, replaces each detected secret with the fake prescribed by the matching Pattern, and returns three things: the scrubbed payload, a set of substitution **entries**, and a **session key**. `scrub` MUST NOT modify bytes outside the detected secrets. `scrub` accepts a single complete payload buffer; streaming input is not part of the API.

**Entries** are the set of substitution records produced by one `scrub` call — one record per distinct secret detected. Each entry holds the fake bytes and the ciphertext of the original secret, encrypted under the session key. Entries are not confidentiality-sensitive on their own: without the session key, the ciphertext is opaque. An observer who sees the entries learns the exact byte length of each detected secret and, for Tier 2 entries, can infer the approximate character class of the fake (which by default is drawn from a wide standard charset unrelated to the secret's content). No plaintext secret bytes appear in entries. The session key remains the sole decryption gate.

**Session key** is a 32-byte random value generated fresh at `scrub` time. It is the sole decryption gate for the entries produced in that call. The session key is sensitive and ephemeral: it exists in process memory for one request/response cycle only, MUST NOT be written to disk, and MUST NOT appear in logs or any serialized form. Entries and session key are explicitly separate values with separate sensitivity levels and separate lifetimes.

**`unscrub`** receives a response stream, the entries from the corresponding `scrub` call, and the session key. It performs exact multi-string matching using only the fake byte strings in the entries — no pattern detection, no charset scanning. Every match triggers decryption of the corresponding entry; the original bytes are emitted in place of the fake. Bytes that do not match any fake are forwarded unchanged. `unscrub` MUST NOT require the full response to be buffered before emitting output.

**Registration** is a preparatory operation that takes a secret value and produces a Tier 2 Pattern. The secret is consumed during registration and immediately discarded; the library has no persistent store. The produced Pattern is an opaque value the caller holds and passes to future `scrub` calls. Registration is described in detail under Detection Tiers.

These operations and data abstractions are the complete public surface. The only caller-visible configuration beyond Patterns is `RegistrationOptions`, which controls opt-in prefix/suffix preservation and charset restriction for Tier 2 registrations.

## Detection Tiers

### Tier 1 — Known Secret Classes

Tier 1 covers secrets whose format is structurally well-known. Each Tier 1 pattern is defined as an ordered sequence of structural segments. A segment is either a **Literal** — a fixed byte sequence that must appear exactly at the current position — or a **Variable** — a character set with a minimum and maximum length, where every byte must belong to that set.

Detection is structural: at each byte position, walk the segment sequence against the payload. A Literal segment must match its fixed bytes exactly. A Variable segment consumes bytes that all belong to the segment's character set, within the segment's length range; when a Variable segment is followed by a Literal, the boundary is found by searching for that Literal within the valid range — this handles embedded fixed markers within an otherwise variable payload. No full regular expression engine is used; detection is a bounded linear scan with no backtracking. Detection records how many bytes each Variable segment consumed; that per-segment length drives fake generation.

The fake for a Tier 1 match reproduces every Literal segment verbatim and fills each Variable segment with the same number of bytes drawn from that segment's character set, sampled from a CSPRNG. The fake has the same total byte length as the original.

The library MUST ship built-in Tier 1 definitions covering at minimum: Anthropic API keys, OpenAI API keys, AWS IAM access key IDs, GitHub personal access tokens (classic and fine-grained), and GCP API keys. Additional definitions MAY be added; the built-in set is not closed.

Each built-in Tier 1 definition is a single canonical Pattern value; the library exposes one Pattern per class. A caller that reuses the same Pattern instance across `scrub` calls will always receive the same fake for the same secret, enabling cross-call stability.

### Tier 2 — Registered Arbitrary Secrets

Tier 2 covers secrets that do not conform to any known structural class. The caller performs a **registration** operation (described below) that produces a Tier 2 Pattern. That Pattern is then passed to `scrub` exactly like a Tier 1 Pattern; `scrub` applies all Patterns uniformly.

Detection: when a start fragment matches, the candidate is confirmed by verifying the end fragment at the expected offset and then computing the HMAC and comparing it against the token stored in the Pattern. A structural match that fails HMAC verification MUST be passed through unchanged; no replacement occurs. HMAC verification is internal to the Pattern's detection logic and does not appear in `scrub`'s output. The detection fragments (start and end bytes of the registered secret) live exclusively in the caller-held Pattern; they are never written to the entries file.
### Registration

Registration is a distinct, preparatory operation that precedes the scrub→unscrub cycle. It takes a secret value and an optional `RegistrationOptions` and produces a `Result<Pattern, RegistrationError>`. The secret value is consumed during registration and immediately discarded; the registration operation MUST NOT store the original secret anywhere.

`RegistrationOptions` controls three opt-in behaviours:

- **`preserve_prefix: usize`** (default `0`). The first N bytes of the secret are declared non-secret by the caller and will be reproduced verbatim at the start of every fake. These bytes MUST appear exactly in every occurrence of the secret in the payload for detection to fire; they serve as the structural anchor and are explicitly not part of the confidential value. Setting this is appropriate when the secret has a well-known, non-secret prefix (e.g., `MY_ORG_`). Misuse — marking actual secret bytes as prefix — weakens protection for those bytes and is the caller's responsibility.

- **`preserve_suffix: usize`** (default `0`). Symmetrically, the last M bytes of the secret are declared non-secret and reproduced verbatim at the end of every fake.

- **`restrict_charset: bool`** (default `false`). When `false`, the variable portion of the fake is drawn from the standard wide charset (`[A-Za-z0-9!@#$%^&*\-_+.~|]`, 72 chars). When `true`, fake bytes are drawn exclusively from the distinct byte values observed in the registered secret, exactly as detected by `charsets::detect`. Use `restrict_charset: true` only when the target system would reject a structurally implausible replacement — the trade-off is that the fake then reveals the secret's character class to any observer of the entries file.

The **variable portion** of a registration is `secret[preserve_prefix .. secret.len() - preserve_suffix]`. Registration MUST return `RegistrationError::NoVariableBytes` if the variable portion is empty (i.e., `preserve_prefix + preserve_suffix >= secret.len()`). Registration MUST return `RegistrationError::TooShort` if the secret is empty. If fake generation exhausts the collision-avoidance retry limit (charset too small relative to variable length), registration MUST return `RegistrationError::CollisionLimit`.

Registration MUST emit a `log::warn`-level diagnostic if the variable portion is shorter than 14 bytes. Registration MUST emit a `log::warn`-level diagnostic if the secret's observed charset is a subset of alphanumeric (`[A-Za-z0-9]`) and `restrict_charset` is `false` — this combination produces a fake that looks structurally different from the original, which may be unexpected.

The produced Pattern encapsulates:
- **Detection fingerprint:** start fragment, end fragment, exact byte length, and an HMAC verification token (salt + digest). _(Domain constraint: HMAC provides confirmation that a structural candidate is the registered secret without requiring the full secret to be stored; the unique salt prevents precomputed lookup attacks against the stored digest.)_
- **Preserved prefix/suffix lengths:** the byte counts declared non-secret by the caller.
- **Fake:** a pre-generated replacement, produced from a CSPRNG at registration time. The fake contains only: the declared non-secret prefix bytes, random bytes from the chosen charset filling the variable portion, and the declared non-secret suffix bytes. No byte from the secret's variable portion appears in the fake.

The salt MUST be unique per registration; salt reuse is prohibited.

The Pattern produced by registration is an opaque value the caller receives and holds. Whether the caller persists it is the caller's concern; the library has no persistent store. The Pattern contains detection fragments (first and last bytes of the secret); treating a serialized Pattern with the same sensitivity as the secret is advisable. At no point after registration does the library have access to the original secret.

## Security Properties

**Entries alone do not leak plaintext secret bytes (confidentiality).** Each entry contains only ciphertext and the pre-generated fake. Without the session key, the ciphertext is opaque. The fake, by default, is drawn from the standard wide charset with no connection to the secret's content; it reveals the exact byte length of the detected secret and nothing else. When `restrict_charset: true` is used, the fake also reveals the approximate character class of the secret — this is a documented trade-off the caller accepts by opting in. The entries are not confidentiality-sensitive in the default configuration.

**Entries are integrity-protected (fake binding).** The AEAD tag covers the fake field as associated data (AAD). Replacing `Entry.fake` after `scrub` produces a tag mismatch at `unscrub` time; no plaintext is emitted. An attacker who can write the entries file but not the session key cannot redirect decryption to an arbitrary trigger.

**Scrubbed payload alone does not leak secrets.** The scrubbed output contains only structurally-equivalent fakes. There are no tokens, markers, indices, or side-channels in the scrubbed payload that reference the original bytes.

**Session key is the trust gate.** The session key is generated fresh at the start of each `scrub` call. It lives in process memory only, for the duration of one request/response cycle. It MUST NOT be written to disk. It MUST NOT appear in logs or any serialized form. When the response cycle ends, no secret material remains anywhere — not in the entries, not on disk, not in the payload.

**Per-entry AEAD encryption.** Each substitution entry is independently encrypted with its own AEAD tag under the session key. `unscrub` decrypts entries one by one as their corresponding fakes are matched in the response stream — it does NOT decrypt the entire entries set upfront. _(Domain constraint: the 192-bit nonce eliminates birthday-bound collision risk for randomly-generated nonces; the AEAD construction provides both confidentiality and ciphertext integrity in a single pass. Cipher agility is deliberately absent — algorithm negotiation introduces downgrade risk and implementation complexity with no benefit in a single-purpose library.)_ Restored plaintext MUST NOT be emitted before the AEAD tag of the matching entry passes verification. A tag failure MUST produce an error; the stream MUST NOT continue with the raw fake or any partially-decrypted bytes in place.

**Tier 1 fake plausibility does not compromise security of the credential value.** Tier 1 fakes reproduce every Literal segment's fixed bytes exactly at the corresponding positions (e.g., the `sk-ant-api03-` prefix and the `AA` terminal marker of an Anthropic key) and fill each Variable segment with characters drawn from that segment's character set. The literal bytes are visible in the fake by design — this is what enables the model to reason about format — but the variable bytes are replaced with CSPRNG output and carry no information about the original.

**Tier 2 detection fragments are confined to the Pattern.** Reliable detection of unstructured secrets requires storing enough of the secret to find it quickly. The start and end fragments live exclusively in the caller-held Pattern and never appear in the entries file. The cost of detection is borne by the Pattern (which may be persisted and should be treated as sensitive), not by the entries.

## Streaming Invariants

`unscrub` operates on a stream of byte chunks. At any point during processing, the maximum number of bytes held without being emitted is bounded by the length of the longest fake across all entries:

```
max_hold = max { |fake_i| : fake_i ∈ entries }
```

This bound MUST hold regardless of stream length, chunk count, or chunk size. For typical secret classes this is on the order of 100–200 bytes.

Bytes that leave the window without matching any fake are emitted immediately. A fake whose bytes are split across a chunk boundary MUST still be found and restored correctly.

When no fake from the entries appears anywhere in the response, the stream MUST be forwarded byte-for-byte unchanged. `unscrub` MUST NOT produce an error in this case.

## Fake Generation

All fakes MUST satisfy:

- **Same length:** the fake has the same total byte count as the original secret.
- **No collision with original:** if generation produces a fake equal to the original secret, the implementation MUST resample until they differ. A fake that equals the original is not a fake.

**Tier 1 fakes** additionally MUST satisfy:

- **Same Literal segments:** the fake reproduces every Literal segment's fixed bytes verbatim at the corresponding byte positions.
- **Same charset per Variable segment:** every byte in a Variable segment of the fake is drawn exclusively from that segment's own character set.

**Tier 2 fakes** are structured as:

```
fake = declared_prefix || random_variable_bytes || declared_suffix
```

where `declared_prefix` and `declared_suffix` are the non-secret bytes the caller opted into preserving (zero length by default), and `random_variable_bytes` fills `secret.len() - preserve_prefix - preserve_suffix` positions drawn from the effective charset (wide by default, secret-detected when `restrict_charset: true` is set). No byte from the secret's variable portion appears in the fake.

The behavioral guarantee is stability: every detection of the same secret under the same Pattern MUST produce the same fake. This applies equally to Tier 1 and Tier 2 Patterns. The mechanism by which stability is achieved is an implementation detail — for example, a keyed derivation from a stable salt embedded in the Pattern. The CSPRNG and collision-avoidance requirements apply to fake generation; once a valid fake has been established for a (secret, Pattern) pair, that fake is returned on all subsequent detections without re-generation.
## CLI Contract

The CLI exposes `scrub` and `unscrub` at the process boundary.

**`scrub`:** reads the complete payload from stdin; writes the scrubbed payload to stdout; writes the entries to a caller-specified path; writes the session key to a caller-specified path. The session key output file MUST be created with mode 0600. No other file permission is acceptable.

**`unscrub`:** reads the response stream from stdin incrementally and writes output to stdout as each chunk resolves. It MUST NOT buffer stdin to completion before writing to stdout. The session key MUST be supplied via the `ITS_CLASSIFIED_KEY` environment variable. A `--key` command-line flag MUST NOT exist. _(Domain constraint: command-line arguments are visible in process listings, `/proc`, and shell history; the environment variable is the only acceptable delivery mechanism.)_

The entries file written by `scrub` contains ciphertext only and is not confidentiality-sensitive on its own. It is integrity-protected: the AEAD tag binds each entry's fake field to its ciphertext, so a tampered entries file produces a decryption error rather than silent secret exfiltration. Deletion of the session key file after `unscrub` completes is the caller's responsibility; the CLI `unscrub` command has no mechanism to locate the file and does not perform this deletion. See Known Limitations.

## Behavioral Invariants

1. `scrub` MUST replace every secret detected by the supplied Patterns with a structurally-equivalent fake.
2. `scrub` MUST NOT modify bytes that are not identified as secrets by the supplied Patterns.
3. `scrub` MUST return entries containing exactly one record per distinct secret substituted in that call, and no records for secrets not substituted.
4. `unscrub` MUST restore every fake present in the response stream to its original bytes, regardless of where chunk boundaries fall.
5. `unscrub` MUST NOT emit restored plaintext before the AEAD tag of the corresponding entry has been verified.
6. An AEAD tag failure MUST produce an error; the stream MUST NOT continue with a raw fake or any partially-decrypted content in its place.
7. `unscrub` MUST forward all bytes unchanged when no fake from the entries appears in the stream; it MUST NOT produce an error in this case.
8. `unscrub` MUST NOT hold more than `max { |fake_i| : fake_i ∈ entries }` bytes unemitted at any point during processing.
9. The entries MUST NOT contain plaintext bytes from the variable portion of any registered secret in any field or serialized form. Bytes declared non-secret via `preserve_prefix`/`preserve_suffix` MAY appear in the fake field; their presence is an explicit, caller-acknowledged trade-off. The session key MUST NOT be serialized together with or embedded within the entries.
10. The session key MUST NOT be written to disk, appear in logs, or be included in any serialized form.
11. The session key MUST NOT be retained after the response cycle ends. The entries MUST NOT be retained after the response cycle ends.
12. All key material MUST be destroyed (overwritten with zeros or equivalent) when the session key's response cycle ends; key material MUST NOT remain accessible after the cycle terminates.
13. The same secret detected under the same Pattern MUST produce the same fake. This applies to both Tier 1 and Tier 2 Patterns: within any context where the same Pattern and the same secret appear, the resulting fake is identical.
14. Multiple occurrences of the same secret within a single `scrub` call each produce the same fake in the scrubbed output; all occurrences share a single entry.
15. A fake MUST NOT equal the original secret; if the CSPRNG produces a collision during fake generation, the implementation MUST resample until they differ.
16. A Tier 2 candidate that matches structurally but fails HMAC verification MUST be passed through unchanged; no replacement occurs.
17. Each Tier 2 registration MUST use a unique HMAC salt; salt reuse is prohibited.
18. Detection MUST produce leftmost-longest matches; overlapping matches MUST NOT be produced. This guarantee applies across all Patterns: when two Patterns both match at the same byte position, the longer match takes precedence. If a Tier 1 Pattern and a Tier 2 Pattern both match at the same byte position with the same byte length, the Tier 1 Pattern takes precedence.
19. `unscrub` MUST perform only exact matching against fake byte strings from the entries; it MUST NOT run pattern detection of any kind.
20. The CLI `unscrub` command MUST accept the session key only via the `ITS_CLASSIFIED_KEY` environment variable; no other delivery mechanism is provided or accepted.
21. The CLI `scrub` command MUST create the session key output file with permission mode 0600.
22. The built-in Tier 1 set MUST cover Anthropic API keys, OpenAI API keys, AWS IAM access key IDs, GitHub personal access tokens (classic and fine-grained), and GCP API keys.
23. `scrub` called on a payload containing no detectable secrets MUST return the payload bytes unchanged and an empty entries set.
24. The AEAD tag for each entry MUST cover the entry's fake field as associated data (AAD). Replacing `Entry.fake` after encryption MUST cause `unscrub` to return an error; no original secret bytes MUST be emitted.
25. Tier 2 `register` MUST return `RegistrationError::TooShort` for empty secrets, `RegistrationError::NoVariableBytes` when `preserve_prefix + preserve_suffix >= secret.len()`, and `RegistrationError::CollisionLimit` when fake generation exhausts retries. It MUST NOT panic on any input.
26. Tier 2 `register` MUST emit a `log::warn`-level diagnostic when the variable portion of the registered secret is shorter than 14 bytes.
27. Tier 2 `register` MUST emit a `log::warn`-level diagnostic when the secret's observed byte set is a subset of `[A-Za-z0-9]` and `restrict_charset` is `false`.
28. Every Literal segment in a matched Tier 1 Pattern MUST appear verbatim at the corresponding byte positions of the fake.
29. Every Variable segment in a Tier 1 fake MUST contain only bytes drawn from that segment's own character set.

## Verifiable Conditions

1. Given a payload containing a Tier 1 secret, the scrubbed output contains no byte subsequence equal to the original secret.
2. Given a scrubbed payload, the corresponding entries, and the session key, passing the scrubbed payload through `unscrub` produces bytes that exactly equal the original payload.
3. Two `scrub` calls on the same secret under the same Pattern produce identical fake bytes in the output.
4. Given a response where a fake straddles a chunk boundary, `unscrub` restores the original secret correctly.
5. Given a response that contains no fake from the entries, `unscrub` produces output byte-for-byte identical to the input and returns no error.
6. Given an entries set where one entry's AEAD tag has been tampered with, `unscrub` returns an error and emits no partially-restored output.
7. The entries produced by `scrub` contain no byte sequence from the variable portion of any registered secret, regardless of serialization. Bytes declared non-secret via `preserve_prefix`/`preserve_suffix` MAY appear in the fake field by design.
8. The session key file created by the CLI `scrub` command has permission mode 0600.
9. The CLI `unscrub` command begins writing to stdout before stdin reaches EOF when the input is a live SSE stream.
10. Multiple occurrences of the same secret within a single payload each produce the same fake bytes in the scrubbed output.
11. A Tier 2 candidate that shares start and end fragments with a registered secret but does not match the HMAC passes through the scrubbed payload unchanged.
12. Given an empty set of patterns, `scrub` returns the payload unchanged and an empty entries set.
13. Given a Tier 1 secret whose pattern contains a Literal segment that is not the leading element (e.g., a fixed suffix or an embedded marker), the fake produced by `scrub` reproduces that Literal segment verbatim at the correct byte position.

## Known Limitations / Accepted Trade-offs

- **Best-effort coverage.** Detection finds high-confidence structural matches. Secrets that are obfuscated, encoded, split across tokens, or otherwise transformed before the payload is constructed are out of scope. Entropy-based heuristic detection is excluded: false-positive avoidance takes priority over recall.
- **Tier 2 detection fragments in Pattern.** Reliable detection of unstructured secrets requires storing enough of the secret to locate it. The first and last bytes of the registered secret (start and end fragments) are stored in the caller-held Pattern and never written to the entries file. Callers who persist Patterns should treat them with the same sensitivity as the secret itself.
- **Cross-request correlation.** Because fakes are stable for the lifetime of a Pattern, an observer with access to multiple scrubbed payloads can correlate any two payloads that used the same Pattern — they will share the same fake. This applies equally to Tier 1 and Tier 2 Patterns. This is the accepted cost of fake stability.
- **Body bytes only.** Header inspection is out of scope. The deployment target is local developer tooling, not a TLS-terminating proxy with visibility into all traffic metadata.
- **Compressed and binary payloads.** Matching operates on raw bytes. Payloads that are compressed, encrypted, or encoded before reaching this library are not covered.
- **Single-session entries.** The entries and session key are designed for exactly one request/response cycle. They are not sharable across processes and are not valid after the cycle ends. The session key is intentionally ephemeral.
- **Session key file deletion is caller responsibility.** The CLI `unscrub` command receives the session key value via environment variable but has no specified mechanism to locate the key file. Deletion of the key file after `unscrub` completes is an operational step the caller must perform.
