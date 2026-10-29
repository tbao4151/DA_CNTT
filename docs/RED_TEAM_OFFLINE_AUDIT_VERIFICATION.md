# Independent offline Red Team planning-audit verification

This is a **read-only reproducibility check**, not authentication of Blue Team
detections, a network attack, or proof of Host-only isolation. The Red Team
Streamlit page exports an operator-entered JSON chronology. The verifier
replays each UCB1/random proposal against prior linked feedback, checks the
entire JSON export envelope and rejects duplicate JSON keys, NaN/Infinity,
unknown fields, forged verified outcomes, invalid ordering and oversized files.

On Windows Python 3.12.9, export the timeline in the Red Team UI and store it
**outside the public Git repository**, for example
`C:/DA005-private/red-team/offline-audit.json`. Record its exact SHA-256
**independently before later analysis**, e.g.:

```powershell
$path = "C:/DA005-private/red-team/offline-audit.json"
$pin = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
$pin
py -3.12 scripts/verify_red_team_planning_audit.py `
  --audit $path `
  --expected-sha256 $pin
```

Without `--expected-sha256`, the verifier still checks internal schema and
reproducible decisions but reports `independent_pin_verified=false`.
Recomputing the pin from a modified export defeats the independent integrity
check. A passing check proves only internal consistency with a separately
recorded digest, **not authorship or factual correctness**. Operator-entered
`blue_flagged` observations remain unverified, and UI timestamps are not
network-event, detection or SOC-case timestamps. The verifier does not load
PCAPs, models or SQLite, and never generates traffic or writes files.

Run synthetic cross-platform regression:

```powershell
py -3.12 -m pytest -q tests/test_red_team_audit_verify.py
```

For a scientific Red AI vs random study, collect authorized independently
labeled captures, verify VMware Host-only isolation and establish Blue Team
outcomes from separate evidence. This planning audit cannot substitute for
those steps.
