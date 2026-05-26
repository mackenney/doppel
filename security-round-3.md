# Security Round 3 — CLI Surface & Operational Security

**Date:** 2026-05-25  
**Reviewer role:** Security researcher  
**Files audited:** `src/main.rs`, `src/unscrub.rs`, `src/crypto.rs`, `src/types.rs`, `src/scrub.rs`, `src/tier1.rs`, `src/tier2.rs`, `src/fake.rs`, `tests/e2e/cli.rs`

Full artifact: `artifacts/investigations/security-round-3-cli.md`

---

## Finding Summary

| Ref | Severity | Title | Invariant |
|-----|----------|-------|-----------|
| F-1 | **MEDIUM** | Key file mode not enforced for pre-existing files | INV-21 |
| F-2 | **MEDIUM** | stdout LineWriter buffering may delay chunk emission to downstream consumer | SPEC §CLI / VC-9 |
| F-3 | **MEDIUM** | Intermediate key copies (`key_hex`, `key_bytes`, `hex_key`) not zeroized | INV-12 |
| F-4 | LOW | `ITS_CLASSIFIED_KEY` env var not cleared after reading | — |
| F-5 | LOW | VC-9 e2e test does not actually verify streaming timing | VC-9 |
| F-6 | LOW | Entries file overwrite is non-atomic under SIGINT | — |
| F-7 | LOW | SIGINT between stdout write and key file write → permanently unscrubable output | — |
| F-8 | CLEAN | INV-20 clap struct has no hidden key delivery mechanism | INV-20 |
| F-9 | INFO | hex_encode non-constant-time (no attack vector) | — |
| F-10 | INFO | scrub() HashMap holds plaintext without zeroization (SPEC non-goal) | — |

---

## F-1 · MEDIUM — Key file mode bypass for pre-existing files (INV-21)

**Location:** `src/main.rs:62–70`

```rust
std::fs::OpenOptions::new()
    .write(true).create(true).truncate(true)
    .mode(0o600)   // only applies when O_CREAT creates a NEW file
    .open(path)?;
```

**Root cause:** The `mode` argument to `open(2)` is applied only when `O_CREAT` creates a new file. For an existing file, `O_TRUNC` clears content but permissions are unchanged. Verified empirically: a file pre-existing with 0o644 keeps 0o644 after this call.

**Attack scenario:** A previous interrupted run leaves the key file on disk. The next run with the same `--key-out` path overwrites content but not permissions. If the file was ever chmod'd to 0644 (by the user or a misconfiguration), the session key is written world-group-readable.

**Test gap:** Both `test_inv21_cli_scrub_key_file_mode_0600` (spec) and `test_e2e_key_file_mode_0600` (e2e) use fresh temp directories; neither covers the pre-existing-file case.

**Fix options:**
- Delete the file before open, then use `O_CREAT|O_EXCL|mode(0600)` (atomic creation, fails if exists)
- Write first, then explicitly `set_permissions(path, Permissions::from_mode(0o600))` (always corrects permissions post-write)

---

## F-2 · MEDIUM — stdout LineWriter buffering breaks streaming for non-newline streams (SPEC §CLI / VC-9)

**Location:** `src/main.rs:107–112`, `src/unscrub.rs:76–98`

**Root cause:** `io::stdout()` wraps a `LineWriter<StdoutRaw>` (a newline-triggered `BufWriter` with an 8 KB internal buffer). Every `output.write_all()` call in `unscrub()` deposits bytes into this buffer. No `flush()` is ever called. Bytes reach the downstream file descriptor only when a `\n` appears, the buffer fills to 8 KB, or the process exits.

**Impact by stream type:**
- SSE streams (`data: {...}\n\n`): `\n` triggers `LineWriter` flush — streaming works correctly in practice.
- JSON without trailing newlines, binary streams: output is buffered up to 8 KB per chunk.

**SPEC violation:** "It MUST NOT buffer stdin to completion before writing to stdout" — the application reads incrementally and calls `write_all()` per chunk, but the OS-level output is blocked by the `LineWriter` buffer. For non-newline streams, data does not reach the downstream consumer until the buffer fills.

**Test gap:** The e2e test `test_e2e_unscrub_streams_before_eof` (labeled VC-9) calls `stdout.read_to_end()`, which blocks until the process exits — not until the first byte appears. The test verifies round-trip correctness only; a fully-buffered implementation passes it unchanged.

**Fix:** Add `output.flush()?` after each `write_all()` in `unscrub()`'s emit path. Also strengthen the VC-9 test to confirm output arrives before stdin EOF.

---

## F-3 · MEDIUM — Intermediate key copies not zeroized (INV-12)

**Location:** `src/main.rs:94–100`, `src/main.rs:57–58`

INV-12: "All key material MUST be destroyed (overwritten with zeros or equivalent) when the session key's response cycle ends."

`SessionKey` correctly derives `ZeroizeOnDrop` for the 32-byte key. But three intermediate copies are not zeroized:

| Variable | Type | Contents | Zeroized? |
|----------|------|----------|-----------|
| `key_hex` (in `run_unscrub`) | `String` | 64-char hex key | ✗ |
| `key_bytes` (in `run_unscrub`) | `Vec<u8>` | raw key bytes | ✗ |
| `hex_key` (in `write_key_file`) | `String` | 64-char hex key | ✗ |

After these variables are dropped, their heap allocations contain key material until reclaimed by the allocator.

**Fix:** Use `zeroize::Zeroizing<String>` and `zeroize::Zeroizing<Vec<u8>>` wrappers, which call `zeroize()` on the underlying bytes on drop.

---

## F-4 · LOW — `ITS_CLASSIFIED_KEY` remains in process environment

**Location:** `src/main.rs:94–95`

`std::env::var("ITS_CLASSIFIED_KEY")` is called but `std::env::remove_var("ITS_CLASSIFIED_KEY")` is never called. The key persists in `environ` for the full process lifetime, visible in `/proc/self/environ` and inheritable by any future child process. No child processes are spawned in the current implementation, but the hygiene gap leaves a path for future regressions.

**Fix:** Call `std::env::remove_var("ITS_CLASSIFIED_KEY")` immediately after reading the value.

---

## F-5 · LOW — VC-9 e2e test does not verify streaming (test gap)

**Location:** `tests/e2e/cli.rs:92–164`

The test sends stdin in two halves with a 50 ms sleep, then calls `stdout.read_to_end()` — which blocks until the child process exits. It asserts correctness of the final output but does not verify that any bytes appear during the sleep window. A fully-buffered implementation passes the test unchanged.

**Fix:** Move stdout reading to a separate thread; assert that at least N bytes appear within the 50 ms window before the second stdin half is written.

---

## F-6 · LOW — Entries file write non-atomic

**Location:** `src/main.rs:47`

`std::fs::write(entries_path, ...)` is not atomic. SIGINT mid-write leaves a partial JSON file. If the path already has entries from a prior run, they are truncated before the new write begins — a SIGINT then leaves an empty or partial file.

**Fix:** Write to a `.tmp` side-file and `rename` atomically.

---

## F-7 · LOW — SIGINT window between stdout and key file

**Location:** `src/main.rs:44–49`

Execution order: (1) scrubbed payload to stdout, (2) entries to file, (3) key to file. If SIGINT arrives after (1) but before (3), the caller has a scrubbed payload with no key to unscrub it. Not a security breach — no secret leakage — but data is permanently lost. An accepted operational trade-off of the current sequential design.

---

## F-8 · CLEAN — INV-20 clap struct (no hidden key mechanism)

**Location:** `src/main.rs:27–33`

```rust
Unscrub {
    #[arg(long)]
    entries: PathBuf,
    // NO --key flag
},
```

The `Unscrub` variant has exactly one field. No `env()` directive, no `default_value`, no hidden `#[arg(hide = true)]` field, no `value_parser` with side effects. The session key can only be supplied via `ITS_CLASSIFIED_KEY`. **INV-20 correctly implemented.**

---

## F-9 · INFO — hex_encode non-constant-time

`hex_encode` uses `format!("{:02x}", b)` which has variable timing. This is a file-write utility, not a cryptographic comparison; no timing oracle exists. Non-issue.

---

## F-10 · INFO — scrub() HashMap retains plaintext (SPEC non-goal)

`seen: HashMap<Vec<u8>, usize>` holds plaintext secret bytes during the scrub pass. Dropped without zeroization. Within SPEC non-goal: "Defense against a compromised host or a malicious caller with access to process memory." The window is bounded to one `scrub()` call. Accepted.

---

## Areas Confirmed Clean

| Area | Status |
|------|--------|
| INV-20: `--key` flag absent from clap struct and `--help` output | ✓ |
| INV-20: no `env()` directive on any `Unscrub` field | ✓ |
| INV-21: mode 0600 applied atomically for **new** files via `open(O_CREAT, 0600)` | ✓ |
| Key in `argv` / `/proc/PID/cmdline` | ✓ (env var only) |
| Error messages printing key bytes or plaintext secrets | ✓ (none do) |
| Entries JSON: no plaintext secrets in any field | ✓ (all AEAD ciphertext) |
| AEAD tag verified before plaintext emitted (INV-5) | ✓ |
| `SessionKey` 32-byte key proper zeroized on drop | ✓ (`ZeroizeOnDrop`) |
| Hex encoding timing side-channel on comparison | N/A (encoding only, no comparison) |
