# Step 02 — `secrets-example.toml` fixes

**Wave:** 0 (parallel with step-01 and step-03)
**Status:** ⬜ pending

## Context

`secrets-example.toml` ships 15 of the 27 built-in patterns plus a commented instance-
pattern example. Two issues:

1. **Missing disclaimer**: no indication the file is a 15/27 excerpt; a user reading it
   could believe `doppel init` generates exactly these 15 patterns.
2. **Wrong segment type in instance example**: the commented instance pattern block shows
   `type = "literal"` for the first segment. But `secrets.rs::register()` always generates
   an `opaque` segment for the detection anchor bytes, not a `literal`. A `literal` segment
   is reproduced verbatim in every fake; an `opaque` segment is re-derived from the
   anchor's charset, which is the correct behaviour for registered secrets.

## Prerequisites

- Working directory: `/home/ignacio/pr/doppel/.wt/spec-unified-pattern`
- No prior steps required

## Files to read before editing

Read `secrets-example.toml` in full to get current `LINE#HASH` anchors:
- Line 1 (version line at top of file)
- Lines 275–294 (the commented instance-pattern block near the end)

## Implementation tasks

### 1 — Add header disclaimer comment at top of file

Insert a comment block at the very top of `secrets-example.toml`, before `version = 3`.

**Text to insert (4 lines):**
```toml
# Example patterns file — shows 15 of the 27 built-in structural patterns.
# `doppel init` generates the full set of 27 patterns with freshly generated salts.
# Do not use these salts in production; run `doppel init` to get unique ones.

```

The existing `version = 3` line must remain as-is immediately after the blank line.

### 2 — Fix the instance-pattern segment type

Locate the commented block near the end of the file (currently around line 275+). Find
the lines:

```toml
# [[pattern.segments]]
# type = "literal"
# value = "db_"
```

Replace `# type = "literal"` with `# type = "opaque"` and add an inline comment
explaining it is the detection anchor:

```toml
# [[pattern.segments]]
# type = "opaque"                    # first anchor_len bytes of the secret
# value = "db_"
```

The `# value = "db_"` line stays unchanged. Only the type changes and the comment is
added on the same line as the type.

## What NOT to change

- Do not alter any of the 15 `[[pattern]]` entries (salt values, segment definitions,
  identifiers).
- Do not alter the `# [[pattern.segments]] type = "variable"` block below the fixed
  segment.
- Do not add any section-separator comments.

## Acceptance criteria

```sh
cd /home/ignacio/pr/doppel/.wt/spec-unified-pattern

# File still parses as valid TOML (strip comment lines and validate):
python3 -c "
import tomllib, sys
data = open('secrets-example.toml').read()
# Remove comment-only lines to simulate the active TOML
active = '\n'.join(l for l in data.splitlines() if not l.lstrip().startswith('#'))
tomllib.loads(active)
print('TOML valid')
"

# The 15 pattern entries are still present:
python3 -c "
data = open('secrets-example.toml').read()
active = '\n'.join(l for l in data.splitlines() if not l.lstrip().startswith('#'))
import tomllib
d = tomllib.loads(active)
assert len(d['pattern']) == 15, f'expected 15 patterns, got {len(d[\"pattern\"])}'
print('15 patterns present')
"

# Full test suite still passes:
cargo nextest run --workspace
```

## Reviewer instructions

After the worker completes, verify:

1. File starts with the 3-line disclaimer comment block (no `version` line on line 1).
2. The first non-comment, non-blank line is `version = 3`.
3. Near the end, the commented instance-pattern block contains `# type = "opaque"` (not
   `# type = "literal"`).
4. The `# value = "db_"` line is still present immediately below the type line.
5. The 15 active `[[pattern]]` entries are unchanged (check `identifier` list).
6. No section-separator comments introduced.
