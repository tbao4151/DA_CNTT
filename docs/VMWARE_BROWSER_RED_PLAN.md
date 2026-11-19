# DA005 — Red Team UCB1 selection on the local VMware progress screen

The local /vmware-progress page now offers an OPTIONAL **Mở biên nhận Red Team** file input. It reads a private .red-plan.json produced by the version-2 SHA-pinned local operator CLI, never sends the file to FastAPI, and shows the selected fixed benign scenario, strategy, seed, number of operator feedback rows and claimed operator profile SHA-256.

First open or follow the associated progress JSONL, then import a Red receipt whose filename exactly matches the progress basename:

    session-001.jsonl
    session-001.red-plan.json

Alternatively choose **Mở cặp JSONL + Red** and select exactly both matching files in a single browser file-picker action. The dashboard parses and applies the pair atomically: an invalid/mismatched pair clears the prior timeline and Red selection instead of leaving stale evidence visible. This paired import is a local, read-once viewer action; it neither starts VMware nor follows future file writes. For live stage updates, continue using **Theo dõi tệp đang ghi**, then import the separate receipt when available.

The viewer rejects unmatched names, malformed/oversized receipts, duplicate/unexpected fields, invalid strategy or seed, forged claims of attacks/detections/SOC cases and unbounded feedback counts. Importing another JSONL file or closing the session clears any previous Red selection; a corrupt receipt also clears the preceding selection. No browser network upload is performed.

This UI accepts **software planning provenance only**. It does not re-read the original independently pinned private profile, recompute UCB1, prove execution, verify consent, check Zeek or read real packet captures. The backend version-2 CLI performs the profile SHA + UCB1 approval checks; this separate browser view only checks a redacted self-contained receipt and its local filename correspondence. A forged receipt with fields that satisfy the schema can still be displayed: do NOT treat this UI as evidence of actual attacks, Blue inference, model accuracy or SOC activity.

The original version-1 profile has no Red planning receipt; the UI should show "Chưa có biên nhận" rather than invent UCB1 output. The automated-lab SYNTHETIC REPLAY remains entirely separate. See docs/VMWARE_PINNED_RED_POLICY.md for how the operator-approved policy is constructed and why manual blue_flagged feedback cannot be treated as independently verified ground truth.

Production Chromium regressions in frontend/scripts/vmware-progress-browser-smoke.mjs and frontend/scripts/vmware-python-browser-e2e.mjs cover standalone and genuine Python paired imports, mismatched filenames, forged attack flags, session resets and zero HTTP uploads. No physical VMware network activity is performed in CI.
