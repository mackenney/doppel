# Progress

## Status
Step 01 complete

## Tasks
- [x] Step 01: Key file permission race PoC and findings

## Files Changed
- `plans/exploit-filesystem-race/step-01-findings.md` — confirmed vulnerability, strace evidence, all 4 criteria met
- `artifacts/exploits/verify-key-race.sh` — kernel behavior verification script
- `artifacts/exploits/exploit-key-race.sh` — full race attack PoC

## Notes
CONFIRMED VULNERABLE: pre-create key file at 0644, victim scrub ignores mode=0600 on existing inode.
Kernel: 6.8.0-117-generic, ext4. Session key fully readable after attack.
