# Progress

## Status
Step 02 complete

## Tasks
- [x] Step 01: Key file permission race PoC and findings
- [x] Step 02: /proc/PID/environ session key extraction PoC and findings

## Files Changed
- `plans/exploit-filesystem-race/step-01-findings.md` — confirmed vulnerability, strace evidence, all 4 criteria met
- `artifacts/exploits/verify-key-race.sh` — kernel behavior verification script
- `artifacts/exploits/exploit-key-race.sh` — full race attack PoC
- `plans/exploit-filesystem-race/step-02-findings.md` — confirmed /proc environ leak, all 4 criteria met
- `artifacts/exploits/verify-proc-environ.sh` — self-contained VULNERABLE confirmation script
- `artifacts/exploits/exploit-proc-environ.sh` — key extraction given PID or scan

## Notes
Step 01: CONFIRMED VULNERABLE: pre-create key file at 0644, victim scrub ignores mode=0600 on existing inode.
Step 02: CONFIRMED VULNERABLE: ITS_CLASSIFIED_KEY visible in /proc/PID/environ for entire unscrub lifetime. No remove_var call in source. Key extracted exactly (64 hex chars). Persists across 3 consecutive reads.
