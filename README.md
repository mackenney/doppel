# its-classified

Scrubs secrets from arbitrary byte payloads before they leave your machine,
then restores them transparently in the response — including SSE streams.

**Status:** implemented. See [SPEC.md](SPEC.md) for the behavioral contract.

## What it does

```
scrub(payload, patterns)  →  (scrubbed_payload, ScrubHandle)
unscrub(response_stream, handle, patterns)  →  restored_stream
```

Secrets are replaced with structurally-equivalent fakes: same prefix, same
character set, same length. The model sees a plausible-looking credential and
can reason about its format. The true bytes never leave the machine.

`ScrubHandle` is an ephemeral, session-key-encrypted blob. It holds no
plaintext secrets and is dropped at the end of each request/response cycle.

## Two detection tiers

**Tier 1 — known pattern classes:** built-in structural specs for Anthropic,
OpenAI, AWS, GitHub, GCP keys and more. Detection is a prefix + charset + length
scan; no full regex engine required.

**Tier 2 — registered arbitrary secrets:** for secrets that don't fit a known
class. The caller registers a fingerprint (`start_part`, `end_part`, `length`,
`charset`, plus an HMAC for verification). The full secret is never stored.

## Streaming

`unscrub` works over a stream of `Bytes` chunks. It uses suspicion-driven
buffering: chunks are held only while a potential match is in flight, bounded by
the longest secret length across active patterns (typically 100–200 bytes).
