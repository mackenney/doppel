# doppel — Specification

> The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are used per RFC 2119.

## Purpose

`doppel` intercepts secrets in arbitrary byte payloads, replaces them with structurally-equivalent fakes, and transparently restores the originals in the corresponding output stream — including streaming responses. The threat it addresses is accidental secret exfiltration: secrets that end up in outbound payloads — for example, LLM request bodies — through normal development work (tool output, file contents, environment variables, debug context). Detection is exact and deterministic: any byte sequence matching a declared pattern is replaced without exception. Coverage is limited in the sense that secrets split, base64-encoded, obfuscated, or otherwise transformed before the payload is formed are out of scope; it makes no claim about coverage of transformed forms.

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

**Pattern** is an opaque detection descriptor. It encapsulates everything needed to find a specific secret or secret class in an arbitrary payload and replace it with a structurally-equivalent fake: the detection mechanism, character set, and the stable fake mapping — a per-secret fake deterministically derived from a stable salt embedded in the Pattern on each detection. Built-in pattern constructors generate a fresh ephemeral salt on each call; fakes are stable for the lifetime of one Pattern instance but differ across calls. For persistent cross-call and cross-process stability, load patterns from a patterns file. Both structural patterns and registered secrets produce Pattern values; `swap` treats them identically and is not aware of which kind produced each Pattern.

**`swap`** receives a complete payload and a set of Patterns. It scans for secrets left-to-right, replaces each detected secret with the fake prescribed by the matching Pattern, and returns three things: the swapped payload, a set of substitution **entries**, and a **session key**. `swap` MUST NOT modify bytes outside the detected secrets. `swap` accepts a single complete payload buffer; streaming input is not part of the API.

**Entries** are the set of substitution records produced by one `swap` call — one record per distinct secret detected. Each entry holds the fake bytes and the ciphertext of the original secret, encrypted under the session key. Entries are not confidentiality-sensitive on their own: without the session key, the ciphertext is opaque. An observer who sees the entries learns the exact byte length of each detected secret and, for registered-secret entries, can infer the approximate character class of the fake (which by default is drawn from a wide standard charset unrelated to the secret's content). No plaintext secret bytes appear in entries. The session key remains the sole decryption gate.

**Session key** is a 32-byte random value generated fresh at `swap` time. It is the sole decryption gate for the entries produced in that call. The session key is sensitive and ephemeral: it exists in process memory for one swap/restore cycle only, MUST NOT be written to disk, and MUST NOT appear in logs or any serialized form. Entries and session key are explicitly separate values with separate sensitivity levels and separate lifetimes.

**`restore`** receives a response stream, the entries from the corresponding `swap` call, and the session key. It performs exact multi-string matching using only the fake byte strings in the entries — no pattern detection, no charset scanning. Every match triggers decryption of the corresponding entry; the original bytes are emitted in place of the fake. Bytes that do not match any fake are forwarded unchanged. `restore` MUST NOT require the full response to be buffered before emitting output.

**Registration** is a preparatory operation that takes a secret value and produces a Pattern for a registered secret. The secret is consumed during registration and immediately discarded; the library has no persistent store. The produced Pattern is an opaque value the caller holds and passes to future `swap` calls. Registration is described in detail under Detection Tiers.

These operations and data abstractions are the complete public surface. The only caller-visible configuration beyond Patterns is `SecretOptions`, which controls opt-in prefix/suffix preservation and charset restriction for registered-secret patterns.

## Detection Tiers

### Structural Patterns

Structural patterns cover secrets whose format is structurally well-known. Each structural pattern is defined as an ordered sequence of structural segments. A segment is either a **Literal** — a fixed byte sequence that must appear exactly at the current position — or a **Variable** — a character set with a minimum and maximum length, where every byte must belong to that set.

Detection is structural: at each byte position, walk the segment sequence against the payload. A Literal segment must match its fixed bytes exactly. A Variable segment consumes bytes that all belong to the segment's character set, within the segment's length range; when a Variable segment is followed by a Literal, the boundary is found by searching for that Literal within the valid range — this handles embedded fixed markers within an otherwise variable payload. No full regular expression engine is used; detection is a bounded linear scan with no backtracking. Detection records how many bytes each Variable segment consumed; that per-segment length drives fake generation.

The fake for a structural match reproduces every Literal segment verbatim and fills each Variable segment with the same number of bytes drawn from that segment's character set, derived deterministically from the Pattern's salt. The fake has the same total byte length as the original.

The library MUST ship built-in structural pattern definitions covering at minimum: Anthropic API keys, OpenAI API keys, AWS IAM access key IDs, GitHub personal access tokens (classic and fine-grained), and GCP API keys. Additional definitions MAY be added; the built-in set is not closed.

Each built-in pattern constructor generates a new Pattern with an ephemeral random salt. Reusing the same Pattern instance across `swap` calls produces stable fakes for that session; constructing a new Pattern generates a distinct salt and therefore different fakes. For stable fakes across process restarts and across calls, load patterns from a patterns file.

### Registered Secrets

Registered secrets cover secrets that do not conform to any known structural class. The caller performs a **registration** operation (described below) that produces a Pattern. That Pattern is then passed to `swap` exactly like a structural Pattern; `swap` applies all Patterns uniformly.

Detection: when a start fragment matches, the candidate is confirmed by verifying the end fragment at the expected offset and then computing the HMAC and comparing it against the token stored in the Pattern. A structural match that fails HMAC verification MUST be passed through unchanged; no replacement occurs. HMAC verification is internal to the Pattern's detection logic and does not appear in `swap`'s output. The detection fragments (start and end bytes of the registered secret) live exclusively in the caller-held Pattern; they are never written to the entries file.
### Registration

Registration is a distinct, preparatory operation that precedes the swap→restore cycle. It takes a secret value and an optional `SecretOptions` and returns either a Pattern on success or a `SecretError` on failure. The secret value is consumed during registration and immediately discarded; the registration operation MUST NOT store the original secret anywhere.

`SecretOptions` controls three opt-in behaviours:

- **`preserve_prefix: usize`** (default `0`). The first N bytes of the secret are declared non-secret by the caller and will be reproduced verbatim at the start of every fake. These bytes MUST appear exactly in every occurrence of the secret in the payload for detection to fire; they serve as the structural anchor and are explicitly not part of the confidential value. Setting this is appropriate when the secret has a well-known, non-secret prefix (e.g., `MY_ORG_`). Misuse — marking actual secret bytes as prefix — weakens protection for those bytes and is the caller's responsibility.

- **`preserve_suffix: usize`** (default `0`). Symmetrically, the last M bytes of the secret are declared non-secret and reproduced verbatim at the end of every fake.

- **`restrict_charset: bool`** (default `false`). When `false`, the variable portion of the fake is drawn from the standard wide charset (`[A-Za-z0-9!@#$%^&*\-_+.~|]`, 72 chars). When `true`, fake bytes are drawn exclusively from the distinct byte values observed in the registered secret, exactly as detected by the charset detector. Use `restrict_charset: true` only when the target system would reject a structurally implausible replacement — the trade-off is that the fake then reveals the secret's character class to any observer of the entries file.

The **variable portion** of a registration is `secret[preserve_prefix .. secret.len() - preserve_suffix]`. Registration MUST return `SecretError::NoVariableBytes` if the variable portion is empty (i.e., `preserve_prefix + preserve_suffix >= secret.len()`). Registration MUST return `SecretError::TooShort` if the secret is empty. If fake generation exhausts the collision-avoidance retry limit (charset too small relative to variable length), registration MUST return `SecretError::CollisionLimit`.

Registration MUST emit a `log::warn`-level diagnostic if the variable portion is shorter than 14 bytes. Registration MUST emit a `log::warn`-level diagnostic if the secret's observed charset is a subset of alphanumeric (`[A-Za-z0-9]`) and `restrict_charset` is `false` — this combination produces a fake that looks structurally different from the original, which may be unexpected.

The produced Pattern encapsulates:
- **Detection fingerprint:** start fragment, end fragment, exact byte length, and an HMAC verification token (salt + digest). _(Domain constraint: HMAC provides confirmation that a structural candidate is the registered secret without requiring the full secret to be stored; the unique salt prevents precomputed lookup attacks against the stored digest.)_
- **Preserved prefix/suffix lengths:** the byte counts declared non-secret by the caller.
- **Fake derivation parameters:** the HMAC salt, preserved prefix/suffix lengths, and the resolved charset. The fake is derived deterministically at detection time by seeding a PRNG from `HMAC(salt, candidate || counter)` starting at counter zero. No fake is pre-computed at registration time; no fake bytes are stored in the Pattern.

The salt MUST be unique per registration; salt reuse is prohibited.

The Pattern produced by registration is an opaque value the caller receives and holds. Whether the caller persists it is the caller's concern; the library has no persistent store. The Pattern contains detection fragments (first and last bytes of the secret); treating a serialized Pattern with the same sensitivity as the secret is advisable. At no point after registration does the library have access to the original secret.

### Patterns File

A **patterns file** is a TOML document that carries all data needed to reconstruct Pattern values across process restarts. It contains:

- **Version field** (`version = 2`). The library MUST reject any version other than 2 with a clear error message directing the user to re-run `init`.
- **Structural pattern entries** (`[[structural]]`): an ordered array of tables. Each table has:
  - `identifier` (string): the class identifier, e.g. `"ANTHROPIC_KEY"`.
  - `salt` (string): the 32-byte pattern salt encoded as 64 lowercase hex characters.
  - `segments` (array of inline tables, optional): the ordered segment sequence defining the structural pattern. Each segment is either a **Literal** (`{ type = "literal", value = "<utf-8 string>" }`) or a **Variable** (`{ type = "variable", charset = "<name>", min = <n>, max = <n> }`). Valid charset names are: `alphanumeric`, `url_safe_base64`, `uppercase_alphanumeric`, `digits`, `hex_lower`.
  - When `segments` is present, it overrides the compiled-in definition for that identifier.
  - When `segments` is absent and the identifier matches a compiled-in definition, the compiled-in definition is used.
  - When `segments` is absent and the identifier does not match any compiled-in definition, the library MUST return an error.
  - An entry whose identifier does not match any compiled-in definition is a **user-defined pattern**; its `segments` field is mandatory.
- **Registered secret entries** (`[[registered]]`): an ordered array of tables. Each table has detection fingerprints (start fragment, end fragment, exact length), an HMAC salt, an HMAC digest, and derivation parameters (preserve_prefix, preserve_suffix, optional resolved charset). All binary fields are encoded as lowercase hex strings. An optional `label` (string) field MAY be present for human identification and CLI management.

The patterns file MUST be treated with the same sensitivity as the secrets it detects — it contains detection fragments that serve as a detection oracle. On Unix systems, the file SHOULD be written with mode 0600 (the CLI `init`, `register`, and `define` commands MUST enforce this — see §CLI Contract). The library provides serialization/deserialization functions operating on `&[u8]`/`Vec<u8>`; filesystem operations are the caller's responsibility.

## Security Properties

**Entries alone do not leak plaintext secret bytes (confidentiality).** Each entry contains only ciphertext and the fake bytes. Without the session key, the ciphertext is opaque. The fake, by default, is drawn from the standard wide charset with no connection to the secret's content; it reveals the exact byte length of the detected secret and nothing else. When `restrict_charset: true` is used, the fake also reveals the approximate character class of the secret — this is a documented trade-off the caller accepts by opting in. The entries are not confidentiality-sensitive in the default configuration.

**Entries are integrity-protected (fake binding).** The AEAD tag covers the fake field as associated data (AAD). Replacing `Entry.fake` after `swap` produces a tag mismatch at `restore` time; no plaintext is emitted. An attacker who can write the entries file but not the session key cannot redirect decryption to an arbitrary trigger.

**Swapped payload alone does not leak secrets.** The swapped output contains only structurally-equivalent fakes. There are no tokens, markers, indices, or side-channels in the swapped payload that reference the original bytes.

**Session key is the trust gate.** The session key is generated fresh at the start of each `swap` call. It lives in process memory only, for the duration of one swap/restore cycle. It MUST NOT be written to disk. It MUST NOT appear in logs or any serialized form. When the cycle ends, no secret material remains anywhere — not in the entries, not on disk, not in the payload.

**Per-entry AEAD encryption.** Each substitution entry is independently encrypted with its own AEAD tag under the session key. `restore` decrypts entries one by one as their corresponding fakes are matched in the response stream — it does NOT decrypt the entire entries set upfront. _(Domain constraint: the 192-bit nonce eliminates birthday-bound collision risk for randomly-generated nonces; the AEAD construction provides both confidentiality and ciphertext integrity in a single pass. Cipher agility is deliberately absent — algorithm negotiation introduces downgrade risk and implementation complexity with no benefit in a single-purpose library.)_ Restored plaintext MUST NOT be emitted before the AEAD tag of the matching entry passes verification. A tag failure MUST produce an error; the stream MUST NOT continue with the raw fake or any partially-decrypted bytes in place.

**Structural fake plausibility does not compromise security of the credential value.** Structural fakes reproduce every Literal segment's fixed bytes verbatim at the corresponding positions (e.g., the `sk-ant-api03-` prefix and the `AA` terminal marker of an Anthropic key) and fill each Variable segment with bytes derived from the Pattern's salt. The literal bytes are visible in the fake by design — this is what enables the model to reason about format — but the variable bytes are derived via keyed HMAC and carry no information about the original.

**Registered-secret detection fragments are confined to the Pattern.** Reliable detection of unstructured secrets requires storing enough of the secret to find it quickly. The start and end fragments live exclusively in the caller-held Pattern and never appear in the entries file. The cost of detection is borne by the Pattern (which may be persisted and should be treated as sensitive), not by the entries.

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
- **No collision with original:** if the derived fake equals the original secret, the implementation MUST increment the derivation counter and re-derive. A fake that equals the original is not a fake. In practice this case is unreachable given cryptographic hash properties; the counter mechanism provides a deterministic fallback guarantee.

**Structural fakes** additionally MUST satisfy:

- **Same Literal segments:** the fake reproduces every Literal segment's fixed bytes verbatim at the corresponding byte positions.
- **Same charset per Variable segment:** every byte in a Variable segment of the fake is drawn exclusively from that segment's own character set.

**Registered fakes** are structured as:

```
fake = declared_prefix || derived_variable_bytes || declared_suffix
```

where `declared_prefix` and `declared_suffix` are the non-secret bytes the caller opted into preserving (zero length by default), and `derived_variable_bytes` fills `secret.len() - preserve_prefix - preserve_suffix` positions drawn from the effective charset (wide by default, secret-detected when `restrict_charset: true` is set). No byte from the secret's variable portion appears in the fake. The variable bytes are derived deterministically from the Pattern's HMAC salt and the matched candidate bytes.

The behavioral guarantee is stability: every detection of the same secret under the same Pattern MUST produce the same fake. This applies equally to structural and registered Patterns. Stability is achieved by deterministic derivation: the fake is produced by seeding a PRNG from `HMAC(salt, secret || counter)` where the counter starts at zero and increments only if the derived fake equals the original. Because the derivation is deterministic, the same (salt, secret) always produces the same fake; re-derivation at each detection is equivalent to caching.
## CLI Contract

The CLI exposes `swap`, `restore`, `init`, `register`, `define`, `list`, `inspect`, and `remove` at the process boundary.

**`swap`:** reads the complete payload from stdin; writes the swapped payload to stdout; writes the entries to a caller-specified path; writes the session key to a caller-specified path. The session key output file MUST be created with mode 0600. No other file permission is acceptable.

**`restore`:** reads the response stream from stdin incrementally and writes output to stdout as each chunk resolves. It MUST NOT buffer stdin to completion before writing to stdout. The session key MUST be supplied via the `DOPPEL_KEY` environment variable. A `--key` command-line flag MUST NOT exist. _(Domain constraint: command-line arguments are visible in process listings, `/proc`, and shell history; the environment variable is the only acceptable delivery mechanism.)_

The entries file written by `swap` contains ciphertext only and is not confidentiality-sensitive on its own. It is integrity-protected: the AEAD tag binds each entry's fake field to its ciphertext, so a tampered entries file produces a decryption error rather than silent secret exfiltration. Deletion of the session key file after `restore` completes is the caller's responsibility; the CLI `restore` command has no mechanism to locate the file and does not perform this deletion. See Known Limitations.

**`init`:** creates a new TOML patterns file (version 2) at the caller-specified path. The file includes all built-in structural pattern definitions with their full segment sequences and freshly generated stable salts; the registered secrets list is empty. Because segment definitions are embedded in the output, the file is self-describing and directly editable. The generated file includes a fully-commented block at the end illustrating: (a) an annotated registered-secret entry template with per-field derivation explanations, and (b) the CLI commands available to extend the file (`register`, `define`). The command MUST fail if the file already exists unless `--force` is specified. When `--force` is used, all salts are regenerated — existing fakes produced from the old salts become invalid. The patterns file MUST be written with mode 0600 on Unix.

**`register`:** reads a secret value from stdin (raw bytes, no trimming), loads the patterns file from the caller-specified path, registers the secret as a registered-secret Pattern, appends the new entry to the patterns file, and writes it back. Options `--preserve-prefix`, `--preserve-suffix`, and `--restrict-charset` map to `SecretOptions`. The secret MUST NOT appear in command-line arguments.

**`define`:** adds a user-defined structural pattern to the patterns file. The caller supplies an identifier, one or more segment specifications, and the patterns file path. A fresh stable salt is generated for the new entry. `define` MUST fail if the identifier already exists in the file. `define` MUST fail if the segment list is empty, if any segment specifies an unrecognised charset name, if any Variable segment has `min > max`, or if the segment list contains no Variable segment (a pure-Literal pattern has no variable bytes and cannot produce a structural fake). The patterns file MUST be written back atomically with mode 0600 on Unix.

**`list`:** reads the patterns file and writes a human-readable summary to stdout: each structural pattern entry with its identifier and a human-readable segment description; each registered-secret entry with its label (if present), exact length, and charset summary. `list` MUST NOT modify the patterns file.

**`inspect`:** reads the patterns file and writes full detail for a single pattern to stdout, located by identifier (structural) or label (registered). For a structural entry: all segments and the salt fingerprint (first 8 hex characters of the salt — not the full salt value). For a registered-secret entry: all fields with derivation annotations. `inspect` MUST NOT modify the patterns file.

**`remove`:** removes a pattern from the patterns file by identifier (structural) or label (registered) and writes the updated file back atomically (temporary file plus rename) with mode 0600. `remove` MUST fail if the specified identifier or label is not found. `remove` MUST emit a warning to stderr, but MUST NOT fail, when the target identifier matches a built-in structural pattern — fakes for that pattern class will no longer be produced by `swap`.

**`swap` `--patterns`:** the `swap` subcommand MUST accept a `--patterns <FILE>` argument specifying the patterns file. This argument is required; `swap` MUST NOT fall back to ephemeral patterns when it is absent. The patterns file is loaded before swapping.

## Behavioral Invariants

1. `swap` MUST replace every secret detected by the supplied Patterns with a structurally-equivalent fake.
2. `swap` MUST NOT modify bytes that are not identified as secrets by the supplied Patterns.
3. `swap` MUST return entries containing exactly one record per distinct secret substituted in that call, and no records for secrets not substituted.
4. `restore` MUST restore every fake present in the response stream to its original bytes, regardless of where chunk boundaries fall.
5. `restore` MUST NOT emit restored plaintext before the AEAD tag of the corresponding entry has been verified.
6. An AEAD tag failure MUST produce an error; the stream MUST NOT continue with a raw fake or any partially-decrypted content in its place.
7. `restore` MUST forward all bytes unchanged when no fake from the entries appears in the stream; it MUST NOT produce an error in this case.
8. `restore` MUST NOT hold more than `max { |fake_i| : fake_i ∈ entries }` bytes unemitted at any point during processing.
9. The entries MUST NOT contain plaintext bytes from the variable portion of any registered secret in any field or serialized form. Bytes declared non-secret via `preserve_prefix`/`preserve_suffix` MAY appear in the fake field; their presence is an explicit, caller-acknowledged trade-off. The session key MUST NOT be serialized together with or embedded within the entries.
10. The session key MUST NOT be written to disk, appear in logs, or be included in any serialized form.
11. The session key MUST NOT be retained after the swap/restore cycle ends. The entries MUST NOT be retained after the swap/restore cycle ends.
12. All key material MUST be destroyed (overwritten with zeros or equivalent) when the swap/restore cycle ends; key material MUST NOT remain accessible after the cycle terminates.
13. The same secret detected under the same Pattern MUST produce the same fake. This applies to both structural and registered Patterns: within any context where the same Pattern and the same secret appear, the resulting fake is identical.
14. Multiple occurrences of the same secret within a single `swap` call each produce the same fake in the swapped output; all occurrences share a single entry.
15. A fake MUST NOT equal the original secret; if derivation at counter zero produces a fake equal to the original, the implementation MUST increment the counter and re-derive. If all attempts produce a collision, the implementation MUST return `SecretError::CollisionLimit` rather than emitting the original as a fake.
16. A registered-secret candidate that matches structurally but fails HMAC verification MUST be passed through unchanged; no replacement occurs.
17. Each registration MUST use a unique HMAC salt; salt reuse is prohibited.
18. Detection MUST produce leftmost-longest matches; overlapping matches MUST NOT be produced. This guarantee applies across all Patterns: when two Patterns both match at the same byte position, the longer match takes precedence. If a structural Pattern and a registered Pattern both match at the same byte position with the same byte length, the structural Pattern takes precedence.
19. `restore` MUST perform only exact matching against fake byte strings from the entries; it MUST NOT run pattern detection of any kind.
20. The CLI `restore` command MUST accept the session key only via the `DOPPEL_KEY` environment variable; no other delivery mechanism is provided or accepted.
21. The CLI `swap` command MUST create the session key output file with permission mode 0600.
22. The built-in structural pattern set MUST cover Anthropic API keys, OpenAI API keys, AWS IAM access key IDs, GitHub personal access tokens (classic and fine-grained), and GCP API keys.
23. `swap` called on a payload containing no detectable secrets MUST return the payload bytes unchanged and an empty entries set.
24. The AEAD tag for each entry MUST cover the entry's fake field as associated data (AAD). Replacing `Entry.fake` after encryption MUST cause `restore` to return an error; no original secret bytes MUST be emitted.
25. `register` MUST return `SecretError::TooShort` for empty secrets, `SecretError::NoVariableBytes` when `preserve_prefix + preserve_suffix >= secret.len()`, and `SecretError::CollisionLimit` when fake generation exhausts retries. It MUST NOT panic on any input.
26. `register` MUST emit a `log::warn`-level diagnostic when the variable portion of the registered secret is shorter than 14 bytes.
27. `register` MUST emit a `log::warn`-level diagnostic when the secret's observed byte set is a subset of `[A-Za-z0-9]` and `restrict_charset` is `false`.
28. Every Literal segment in a matched structural Pattern MUST appear verbatim at the corresponding byte positions of the fake.
29. Every Variable segment in a structural fake MUST contain only bytes drawn from that segment's own character set.
30. A user-defined structural pattern MUST specify at least one Variable segment; the `define` command MUST reject a segment list that contains no Variable segment.
31. A user-defined structural pattern identifier MUST be unique within the patterns file; the `define` command MUST fail if the identifier already exists.
32. Removing a built-in structural pattern identifier from the patterns file is permitted and MUST NOT produce an error; `swap` will not apply that pattern class when the identifier is absent from the file.
33. The patterns file version MUST be 2; the library MUST reject any file whose version field is not 2.
34. `list` and `inspect` MUST NOT modify the patterns file.
35. `remove` MUST write the updated patterns file atomically; no partial write MUST be observable by concurrent readers.

## Verifiable Conditions

1. Given a payload containing a secret matching a structural pattern, the swapped output contains no byte subsequence equal to the original secret.
2. Given a swapped payload, the corresponding entries, and the session key, passing the swapped payload through `restore` produces bytes that exactly equal the original payload.
3. Two `swap` calls on the same secret under the same Pattern produce identical fake bytes in the output.
4. Given a response where a fake straddles a chunk boundary, `restore` restores the original secret correctly.
5. Given a response that contains no fake from the entries, `restore` produces output byte-for-byte identical to the input and returns no error.
6. Given an entries set where one entry's AEAD tag has been tampered with, `restore` returns an error and emits no partially-restored output.
7. The entries produced by `swap` contain no byte sequence from the variable portion of any registered secret, regardless of serialization. Bytes declared non-secret via `preserve_prefix`/`preserve_suffix` MAY appear in the fake field by design.
8. The session key file created by the CLI `swap` command has permission mode 0600.
9. The CLI `restore` command begins writing to stdout before stdin reaches EOF when the input is a streaming byte source.
10. Multiple occurrences of the same secret within a single payload each produce the same fake bytes in the swapped output.
11. A registered-secret candidate that shares start and end fragments with a registered secret but does not match the HMAC passes through the swapped payload unchanged.
12. Given an empty set of patterns, `swap` returns the payload unchanged and an empty entries set.
13. Given a secret whose pattern contains a Literal segment that is not the leading element (e.g., a fixed suffix or an embedded marker), the fake produced by `swap` reproduces that Literal segment verbatim at the correct byte position.
14. A user-defined structural pattern defined with identifier `x` and segments `[{ type = "literal", value = "prefix_" }, { type = "variable", charset = "alphanumeric", min = 32, max = 32 }]` detects and replaces a payload containing `prefix_` followed by exactly 32 alphanumeric characters such that no byte of that variable portion appears in the swapped output.
15. `list` output contains the identifier of every structural pattern entry and an identifying label or positional marker for every registered-secret entry present in the patterns file.
16. After `remove` succeeds on an existing identifier or label, the resulting patterns file MUST NOT contain any entry with that identifier or label.

## Known Limitations / Accepted Trade-offs

- **Coverage of transformed secrets.** Detection is exact and deterministic for any byte sequence matching a declared pattern. Coverage is limited in the sense that secrets split across positions, base64-encoded, obfuscated, or otherwise transformed before the payload is formed are not matched. Entropy-based heuristic detection is excluded: false-positive avoidance takes priority over recall.
- **Registered-secret detection fragments in Pattern.** Reliable detection of unstructured secrets requires storing enough of the secret to locate it. The first and last bytes of the registered secret (start and end fragments) are stored in the caller-held Pattern and never written to the entries file. Callers who persist Patterns should treat them with the same sensitivity as the secret itself.
- **Cross-request correlation.** Because fakes are stable for the lifetime of a Pattern, an observer with access to multiple swapped payloads can correlate any two payloads that used the same Pattern — they will share the same fake. This applies equally to structural and registered Patterns. This is the accepted cost of fake stability.
- **Body bytes only.** Header inspection is out of scope. The deployment target is local developer tooling, not a TLS-terminating proxy with visibility into all traffic metadata.
- **Compressed and binary payloads.** Matching operates on raw bytes. Payloads that are compressed, encrypted, or encoded before reaching this library are not covered.
- **Single-cycle entries.** The entries and session key are designed for exactly one swap/restore cycle. They are not sharable across processes and are not valid after the cycle ends. The session key is intentionally ephemeral.
- **Session key file deletion is caller responsibility.** The CLI `restore` command receives the session key value via environment variable but has no specified mechanism to locate the key file. Deletion of the key file after `restore` completes is an operational step the caller must perform.
- **Pre-Aug-2024 OpenAI project key format not detected.** The original `sk-proj-` format (56 chars total, no embedded `T3BlbkFJ` marker, issued before August 2024) is not matched by `OPENAI_PROJECT_DEF`. These keys required only `sk-proj-<48 url_safe_b64>` — structurally indistinguishable from arbitrary base64 without the marker. Keys of this age are expected to have been rotated; best-effort coverage is the explicit contract.
