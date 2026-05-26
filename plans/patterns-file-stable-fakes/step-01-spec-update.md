# Step 01: SPEC.md Update

## Context

### Overall Objective
Make fakes deterministic across process restarts, add a patterns file format, and expose CLI surface for Tier 2 registration and stable salt persistence.

### Phase Context
Wave 0. SPEC.md is the authoritative behavioral contract. It must be updated before implementation begins so workers have a correct reference. This step has no code dependencies.

### This Step
Update SPEC.md to reflect three changes: (1) Tier 2 fakes are now derived deterministically at match time instead of pre-generated at registration, (2) a patterns file contract is documented, (3) CLI contract is expanded with `init`, `register`, and `--patterns`.

## Prerequisites
- None

## Files to Read Before Starting
- `/home/ignacio/pr/its-classified/SPEC.md` — current spec, all 196 lines

## Implementation

### Task 1: Update Core Mental Model (line 24)

In `SPEC.md`, find line 24 which contains:

```
…either a pre-generated fake (Tier 2) or a per-secret fake deterministically derived from the Pattern on each detection (Tier 1).
```

Replace that clause with:

```
…a per-secret fake deterministically derived from a stable salt embedded in the Pattern on each detection (both Tier 1 and Tier 2).
```

The full line 24 after edit should read:

> **Pattern** is an opaque detection descriptor. It encapsulates everything needed to find a specific secret or secret class in an arbitrary payload and replace it with a structurally-equivalent fake: the detection mechanism, character set, and the stable fake mapping — a per-secret fake deterministically derived from a stable salt embedded in the Pattern on each detection (both Tier 1 and Tier 2). Built-in Tier 1 definitions and Tier 2 registrations both produce Patterns; `scrub` treats them identically and is not aware of tier distinctions. Built-in Tier 1 Patterns are canonical singleton values — one per class.

### Task 2: Update Registration §Produced Pattern (line 76)

Find line 76 which contains:

```
- **Fake:** a pre-generated replacement, produced from a CSPRNG at registration time. The fake contains only: the declared non-secret prefix bytes, random bytes from the chosen charset filling the variable portion, and the declared non-secret suffix bytes. No byte from the secret's variable portion appears in the fake.
```

Replace with:

```
- **Fake derivation parameters:** the HMAC salt, preserved prefix/suffix lengths, and the resolved charset. The fake is derived deterministically at detection time from `HMAC(salt, candidate || attempt_counter)` → seeded PRNG. No pre-generated fake is stored in the Pattern.
```

### Task 3: Update Fake Generation §Tier 2 (around line 130)

Find line 130 which reads:

```
where `declared_prefix` and `declared_suffix` are the non-secret bytes the caller opted into preserving (zero length by default), and `random_variable_bytes` fills `secret.len() - preserve_prefix - preserve_suffix` positions drawn from the effective charset (wide by default, secret-detected when `restrict_charset: true` is set). No byte from the secret's variable portion appears in the fake.
```

Append a sentence after "…appears in the fake.":

```
The variable bytes are derived deterministically from the Pattern's HMAC salt and the matched candidate bytes, not from a CSPRNG at registration time.
```

### Task 4: Add Patterns File section (after line 80)

After line 80 (the paragraph ending "At no point after registration does the library have access to the original secret."), insert a new section:

```markdown

### Patterns File

A **patterns file** is a JSON document that carries all data needed to reconstruct `Pattern` values across process restarts. It contains:

- **Version field** (`version: 1`). The library MUST reject unknown versions.
- **Tier 1 entries**: a map of class identifier → 32-byte salt. All other Tier 1 fields (prefix, charset, length bounds) are compiled into the binary and not serialized. A patterns file MUST contain a salt for every built-in Tier 1 class; the library MUST return an error if any class is missing.
- **Tier 2 entries**: an array of detection fingerprints (start/end fragments, exact length, HMAC salt, HMAC digest) plus derivation parameters (preserve_prefix, preserve_suffix, and optionally the resolved charset). No pre-generated fake bytes are stored.

The patterns file MUST be treated with the same sensitivity as the secrets it detects — it contains detection fragments that serve as a detection oracle. On Unix systems, the file SHOULD be written with mode 0600. The library provides serialization/deserialization functions operating on `&[u8]`/`Vec<u8>`; filesystem operations are the caller's responsibility.
```

### Task 5: Expand CLI Contract (lines 133–141)

After the existing CLI Contract section content (after line 141), append:

```markdown

**`init`:** creates a new patterns file at the caller-specified path with all built-in Tier 1 definitions and freshly generated stable salts. The Tier 2 list is empty. The command MUST fail if the file already exists unless `--force` is specified. When `--force` is used, all salts are regenerated — existing fakes produced from the old salts become invalid. The patterns file MUST be written with mode 0600 on Unix.

**`register`:** reads a secret value from stdin (raw bytes, no trimming), loads the patterns file from the caller-specified path, registers the secret as a Tier 2 Pattern, appends the new entry to the patterns file, and writes it back. Options `--preserve-prefix`, `--preserve-suffix`, and `--restrict-charset` map to `RegistrationOptions`. The secret MUST NOT appear in command-line arguments.

**`scrub` `--patterns`:** the `scrub` subcommand MUST accept a `--patterns <FILE>` argument specifying the patterns file. This argument is required; `scrub` MUST NOT fall back to ephemeral patterns when it is absent. The patterns file is loaded via `PatternsFile::deserialize` and `into_patterns` before scrubbing.
```

## Acceptance Criteria

These must ALL pass before reporting complete:

- [ ] `grep -c "pre-generated fake (Tier 2)" /home/ignacio/pr/its-classified/SPEC.md` outputs `0` (old wording removed)
- [ ] `grep -c "deterministically derived from a stable salt embedded in the Pattern on each detection (both Tier 1 and Tier 2)" /home/ignacio/pr/its-classified/SPEC.md` outputs `1`
- [ ] `grep -c "Fake derivation parameters:" /home/ignacio/pr/its-classified/SPEC.md` outputs `1`
- [ ] `grep -c "### Patterns File" /home/ignacio/pr/its-classified/SPEC.md` outputs `1`
- [ ] `grep -c "MUST reject unknown versions" /home/ignacio/pr/its-classified/SPEC.md` outputs at least `1`
- [ ] `grep -c "\-\-patterns" /home/ignacio/pr/its-classified/SPEC.md` outputs at least `1`
- [ ] `grep -c "init.*creates a new patterns file" /home/ignacio/pr/its-classified/SPEC.md` outputs `1`
- [ ] `grep -c "register.*reads a secret value from stdin" /home/ignacio/pr/its-classified/SPEC.md` outputs `1`

## Reviewer Instructions

You are reviewing Step 01. Verify:
1. Run each acceptance criteria command — all must produce the expected output
2. Read the updated SPEC.md and verify:
   - Line 24 no longer mentions "pre-generated fake (Tier 2)"
   - Registration section uses "Fake derivation parameters" instead of "Fake: a pre-generated replacement"
   - A "### Patterns File" subsection exists between Registration and Security Properties
   - CLI Contract section mentions `init`, `register`, and `--patterns`
   - No behavioral invariants (INV-1 through INV-27) were modified or removed
3. Verify the rest of the file is unchanged (no accidental deletions)
Report: "PASS" with each criterion confirmed, or "FAIL: <criterion> — <what's wrong>"

## Rollback
```
git checkout HEAD -- SPEC.md
```
