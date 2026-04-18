# Round 1 — Instructor Notes (DO NOT ship in casefile)

> This file contains the ground-truth answer key, MITRE ATT&CK mapping, reference
> YARA rule, and expected student observations. Keep it inside `module-techlab/`;
> `test_casefile_structure.py` enforces that nothing from this path leaks into
> `module-casefile/`.

## MITRE ATT&CK ground truth for R1

| Observation | Technique | ID |
|---|---|---|
| Xlib/pynput loop captures keystrokes | Input Capture: Keylogging | **T1056.001** |
| `scrot` to `/tmp/screen-<ts>.png` | Screen Capture | **T1113** |
| `open()`/`shutil` reading `~/.bash_history`, `~/.ssh/id_rsa`, `Documents/` | Data from Local System | **T1005** |
| HTTP POST to `10.13.37.1:8080/collect` | Application Layer Protocol: Web | **T1071.001** |
| Exfil over the same channel used as command path | Exfiltration Over C2 Channel | **T1041** |

Any declared TTP outside this set is incorrect for R1. `test_mitre_mapping.py` enforces the allowlist at source level.

## OPSEC posture (R1 baseline — no mistakes, just transparency)

R1 is deliberately naïve. There is nothing "hidden" for students to uncover — the teaching point is that *every detection artifact is in plain sight*. The list of visible artifacts students should name:

1. Process name: literally `python3 /opt/spyware/spyware.py` in `ps -ef`.
2. Open socket to `10.13.37.1:8080` visible in `ss -tnp`.
3. C2 URL embedded as a plaintext string in the binary (`strings /opt/spyware/spyware.py | grep 10.13`).
4. JSON field names (`host`, `user`, `keys`, `files`, `screenshot_bytes`) appear in `tcpdump -A` output.
5. Harvested files are readable from the POST body directly.
6. **Screenshot taken but not exfiltrated (intentional partial-implementation flaw):** `take_screenshot()` saves a PNG to `/tmp/screen-<ts>.png` and reports its file *size* in the POST (`"screenshot_bytes": N`), but never reads or sends the file contents. T1113 (Screen Capture) applies because the screenshot is taken; the file content never reaches the C2, which is an OPSEC flaw the attacker didn't notice. Sharp students examining the JSON payload will see a non-zero `screenshot_bytes` but no corresponding base64 or binary field — a good pivot for discussion. If asked, confirm this is a bug in the attacker's code, not an intentional design.

If a student says "R1 is sophisticated", redirect: R1 is the null hypothesis. OPSEC improvement only begins in R2.

## Reference YARA rule (positive example for the grader)

```yara
rule Ghost_R1_Naive_Spyware
{
    meta:
        author = "instructor"
        description = "Matches the R1 naïve spyware sample"
        round = "1"
        mitre = "T1056.001,T1113,T1005,T1071.001,T1041"
    strings:
        $lab_header = "GHOST-IN-THE-BOX LAB"
        $c2_ip = "10.13.37.1"
        $field1 = "screenshot_bytes"
        $field2 = "\"keys\""
        $import_http = "import exfil_http"
    condition:
        $lab_header and (3 of ($c2_ip, $field1, $field2, $import_http))
}
```

This rule is what the auto-grader uses as a baseline. Student-written rules are graded for precision and recall against the same `module-casefile/round-1/yara-corpus/` that this one was tuned against.

## Expected student deliverables

1. **IOC table** listing process name/path, C2 endpoint, stolen-data types, exfil cadence.
2. **MITRE table** matching the ground truth above (5 techniques).
3. **YARA rule** matching ≥3 strings similar to the reference rule. Precision ≥ 0.95 and Recall = 1.0 on the R1 corpus.
4. **NIST 800-61r2 report** — one page covering Detection (how the process was found), Containment (isolation / kill), Eradication (removal steps), Recovery (verification). Appendix: MITRE mapping.

## Common student mistakes in R1

- Declaring T1036.005 (Masquerading) for R1 — this only applies once the process name is forged (R2).
- Missing T1041 because they only tag T1071.001 — the two coexist in R1 since data exfil rides the same HTTP channel.
- YARA rule with only the `$c2_ip` string — too brittle (any machine with that IP in its notes will false-positive). Encourage ≥3 distinct pivots.
- Report skips Recovery because "there is nothing to restore". Recovery includes verification that traffic has stopped and listing hardening steps for the next round.

## Running the YARA grader

The grader lives at `tests/test_detection_rules.py`. Use pytest for baseline regression (`pytest tests/test_detection_rules.py`) or run it as a CLI for individual student rules:
```bash
python -m tests.test_detection_rules --rule path/to/student.yar --round 1
```
