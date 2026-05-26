# Plan Fix Result

**Date:** 2026-05-25
**Input:** `artifacts/fact-checks/plan-factcheck.md` (34 claims: 29 confirmed, 1 refuted, 3 partial, 1 unverifiable)

---

## Fixes Applied

### Fix 1 — [R1] Step-09: correct test count from 23 → 22

**File:** `plans/initial-implementation/step-09-spec-tests.md`

**Problem:** The acceptance criterion and reviewer check both asserted 23 `test_invN_*`
functions. The step only defines 22 (INV-1 through INV-20, INV-22, INV-23). No
`test_inv21` is present — INV-21 (0600 key file mode) is a CLI-level invariant
correctly covered by step-08 (`stat -c %a` acceptance check) and step-11 (e2e
`PermissionsExt::mode()` test).

**Changes made:**

1. `### This Step` paragraph: changed "all 23" → "all 22", added explicit note that
   INV-21 is CLI-only and covered by step-08 and step-11.

2. `### Task 2` heading: changed "all 23 invariant tests" →
   "22 invariant tests (INV-1 through INV-20, INV-22, INV-23)".

3. **Acceptance criterion** (line ~400): changed
   `All 23 test_invN_* functions present` →
   `All 22 test_invN_* functions present (INV-21 is CLI-only; covered by step-08 and step-11)`.

4. **Reviewer check #2** (line ~410): changed
   `must return 23 (or ≥23)` →
   `must return 22 (INV-21 is CLI-only, verified in step-08 and step-11)`.

5. **Reviewer check #3** (line ~411): changed `must return ≥23` → `must return ≥22`.

**Commit:** `0a1d746` — "Fix plan issues from fact-check"

---

## PARTIAL Claims (not fixed — task scope is REFUTED only)

- **P1** — Step-07 Task 2 first code block uses `entries[entry_idx]` (won't compile); the
  revised "Simplified correct structure" at the end of the same task is correct. Worker
  risk only; no claim is literally false because the correct code is present.
- **P2** — Step-04/05 circular `Tier2Pat` dependency; acknowledged in prerequisites but
  no stub provided. Not a false claim, just an incomplete resolution path.
- **P3** — `thiserror` missing from step-01 Cargo.toml; step-02 instructs adding it.
  Not a false claim; the dependency is noted in step-02, just not pre-populated in step-01.

These are plan risks, not refuted facts. No changes made for P1–P3.
