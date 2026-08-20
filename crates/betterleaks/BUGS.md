# BUGS

Defects — behaviour that is WRONG and should be fixed. Limitations accepted on
purpose live in `PORT-TRACK.md` under their module's deviations, not here.

---

## BUG-001 · A NUL byte in the first 8 KB silently skips the whole file

**Severity: CRITICAL.** Found by `/unravel:port:audit`, 2026-08-14, via seeded
differential fuzzing (`.scripts/40-H_differential_fuzz.ps1`, seed `20260814`).

**What happens.** `sources::file::looks_binary` treats a file as binary if ANY
NUL byte appears in its first 8192 bytes, and the file is then never scanned.
The Go source does something different: `sources/file.go:298` calls
`filetype.Match` and skips only when the sniffed MIME **type is
`application`** — a recognised binary FORMAT. A text file that merely contains a
stray NUL is scanned by Go and skipped here.

**Impact.** A secret in such a file is not reported, and the scan exits 0 saying
`no leaks found`. That is the failure this tool exists to prevent, and it is
silent: nothing in the output distinguishes "scanned and clean" from "never
read".

**Evidence — measured, not argued.** 120 generated files, same inputs to both
binaries:

| | Go | this port |
|---|---|---|
| bytes scanned | 613,989 | 149,177 |
| findings | 418 | 83 |

`ONLY-GO = 335`, `ONLY-RS = 0` — a strict subset, so no false positives, purely
missed detections. The port read **24% of the bytes** and found **20% of the
secrets**.

**Root cause is fully accounted for.** Of the 120 files, 85 contain a NUL in the
first 8 KB (464,812 bytes) and 35 do not (149,177 bytes). Predicted bytes-scanned
if the NUL rule were the only cause: **149,177**. Reported: **149,177**.
Unexplained delta: **0**. One cause, no second bug hiding behind it.

**Minimal repro** (`.scripts/44-H_confirm_nul_fixed.ps1`):

```
junk\0junk
aws_key = AKIA<16 base32 chars>
```

| case | Go | port |
|---|---|---|
| `plain` | 1 | 1 |
| `nul_before` (NUL at offset 4) | 1 | **0** |
| `nul_after` (NUL after the secret) | 1 | **0** |
| `nul_at_8191` (inside the window) | 1 | **0** |
| `nul_at_8193` (outside the window) | 1 | 1 |

The boundary at 8192 confirms the mechanism exactly.

**Why it was not caught earlier.** The deviation IS flagged in
`sources/src/file.rs` and in `PORT-TRACK.md` — but the flag names only the
harmless direction: *"they differ on NUL-free binary formats"*. The dangerous
direction, NUL-CONTAINING files that Go still scans, is not mentioned. Both
corpus differentials use realistic source trees, which rarely contain stray
NULs, so the sample never reached it. Fixed-corpus differentials cannot find
this class; a generator that emits adversarial bytes can.

**Fix.** Replace `looks_binary` with a magic-byte sniff and skip only on an
`application/*` match, which is what `filetype.Match` does. `infer` is the
maintained Rust equivalent and `PORT-TRACK.md` already nominates it. The
regression test must be the `nul_before` case above, and it must fail against
the current code before the fix lands.

**Not affected:** UTF-16 text. Both tools find nothing there (the rules match
UTF-8 bytes), so it is not a divergence — checked rather than assumed.

**Status:** OPEN.

