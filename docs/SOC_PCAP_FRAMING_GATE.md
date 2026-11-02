# DA005 — Classic-PCAP framing gate at manual NEW-log SOC triage

This gate applies only when an operator supplies the optional **original offline
PCAP + offline_import_report.json + conn.log** provenance triplet to
`scripts/triage_zeek_new_log.py` or the Blue Team manual case API.

The existing SHA-256, original-file size, declared CIDR, Zeek flow count, and
research model/report consistency checks remain mandatory. In addition, the
manual triage CLI now requires valid **classic PCAP record framing** when
listing candidates with PCAP provenance, and the SOC write API independently
rechecks that framing before creating or reusing an Unclassified case.
Header-only, truncated packet, impossible captured length, or invalid
fractional timestamp records are refused even if the operator repins both the
PCAP and its import report. No files are modified by this verification.

The optional PCAP provenance input remains optional for legacy manual triage.
Without it, the case note explicitly says original PCAP provenance was NOT
software-checked. A legacy research case is never a confirmed attack or a live
alert. Dataset Mode and its UNSW-NB15 benchmark are unchanged.

## Operator steps (Windows 11, private evidence only)

1. Keep the original PCAP, Zeek `conn.log`, and import report outside Git.
   Record SHA-256 values independently before verification. Do not edit or
   repin failed evidence merely to force a PASS.
2. Follow the existing pinned model, experiment manifest and triage flags
   documented by `python scripts/triage_zeek_new_log.py --help`. Include the
   three `--offline-import-*` arguments and the independent import-report pin.
3. Run `py -3.12 -m pytest -q tests/test_offline_pcap_soc_triage_gate.py`
   to verify the software contract. Then run the actual private, approved
   operator workflow and preserve the exit code and private case export.
4. A refusal means **stop and investigate** the original evidence, not alter
   source bytes. A successful synthetic CI run is not a laptop experiment.

**Scientific boundary:** valid PCAP framing does **not** prove packet payloads
match Zeek five-tuples, timestamps, capture origin, authorization, Host-only
isolation, independently assigned labels, or attack detection. The separate
`scripts/verify_lab_evidence_chain.py` optional tuple/timestamp checks and
manual VMware review remain independent gates. The Zeek model is separate
from the 42-feature UNSW-NB15 model. No network capture, Red Team execution,
automatic alert or public deployment is introduced by this change.
