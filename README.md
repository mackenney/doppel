# its-classified

Scrubs secrets from arbitrary byte payloads before they leave your machine,
then restores them transparently in the response — including SSE streams.

**Status:** implemented. See [SPEC.md](SPEC.md) for the behavioral contract.

## How it works

```
scrub(payload, patterns)  →  (scrubbed_payload, entries, session_key)
unscrub(response_stream, entries, session_key)  →  restored_stream
```

You supply the patterns. `scrub` applies exactly the patterns you pass — nothing
more. Secrets matching those patterns are replaced with structurally-equivalent
fakes before the payload leaves. `unscrub` reverses the substitution in the
response stream using the encrypted entries and the session key.

## Patterns

**You decide what gets scrubbed.** A pattern describes how to detect and replace
one secret or one class of secrets. There are two kinds:

### Tier 1 — structural classes

A Tier 1 pattern describes the *shape* of a secret class: a fixed literal prefix,
a character set, and a length range. Detection fires on any payload byte that
matches that shape; no prior knowledge of the actual secret value is required.

The library ships built-in Tier 1 definitions for common providers (Anthropic,
OpenAI, AWS, GitHub, GCP). These are available as a starting set — you opt into
them; they are not applied automatically.

### Tier 2 — specific known secrets

A Tier 2 pattern covers a secret that has no structural class: you know the
actual value and want it scrubbed wherever it appears. You register the full
secret bytes; the library derives a detection fingerprint and generates a fake
at registration time. The original value is never stored.

```rust
let pat = register(b"im_very_very_very_sneaky")?;
```

`RegistrationOptions` lets you declare a non-secret prefix/suffix (preserved
verbatim in the fake) and restrict the fake's character set to match the
original's.

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

The CLI reads patterns from a file — one entry per line. You maintain this file;
add lines as your secret inventory grows. Each line encodes the full pattern
definition including the salt, so fakes are stable across process restarts.

```
# Tier 1: prefix  charset            length  salt
sk-ant-  url_safe_base64  80-120  a3f1...32hexbytes...
gh_pat_  url_safe_base64  82-100  7d9e...32hexbytes...
AKIA     uppercase_alnum  20-20   c821...32hexbytes...

# Tier 2: secret_value  [options]  salt
im_very_very_very_sneaky  9b2c...32hexbytes...
MY_ORG_secretpart_END  preserve_prefix=7 preserve_suffix=3  salt=f40a...32hexbytes...
```

The library's built-in Tier 1 specs are available as named shortcuts with
pre-seeded salts you can copy into your file as a starting point.

> **Current gap:** the CLI patterns file format and `--patterns` flag are not yet
> implemented. The CLI currently applies all built-in Tier 1 patterns with
> per-process random salts and has no Tier 2 registration surface.
> See Known Gaps in MASTER_PROGRESS.md.

## Streaming

`unscrub` works over a stream of `Bytes` chunks. It uses suspicion-driven
buffering: chunks are held only while a potential match is in flight, bounded by
the longest secret length across active patterns (typically 100–200 bytes).
