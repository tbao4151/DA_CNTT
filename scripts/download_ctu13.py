#!/usr/bin/env python3
"""Download and verify CTU-13 Scenario 7 bidirectional flow logs from CTU."""
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

SOURCE = (
    "https://mcfp.felk.cvut.cz/publicDatasets/"
    "CTU-Malware-Capture-Botnet-48/"
    "detailed-bidirectional-flow-labels/capture20110816-2.binetflow"
)
EXPECTED_FIELDS = [
    "StartTime", "Dur", "Proto", "SrcAddr", "Sport", "Dir", "DstAddr",
    "Dport", "State", "sTos", "dTos", "TotPkts", "TotBytes",
    "SrcBytes", "Label",
]
ROOT = Path(__file__).resolve().parents[1]
TARGET_DIR = ROOT / "data" / "raw" / "ctu13_scenario_07"
TARGET = TARGET_DIR / "capture20110816-2.binetflow"
METADATA = TARGET_DIR / "metadata.json"

def validate(path: Path):
    counts = Counter()
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as file:
        reader = csv.reader(file)
        fields = next(reader)
        if fields != EXPECTED_FIELDS:
            raise ValueError(f"Unexpected header: {fields!r}")
        rows = 0
        for line_number, row in enumerate(reader, 2):
            if len(row) != len(EXPECTED_FIELDS):
                raise ValueError(f"Row {line_number}: expected 15 columns, got {len(row)}")
            label = row[-1]
            if "Background" in label:
                counts["Background"] += 1
            elif "Botnet" in label:
                counts["Botnet-related"] += 1
            elif "Normal" in label:
                counts["Normal"] += 1
            else:
                counts["Other"] += 1
            rows += 1
    if rows < 1000:
        raise ValueError(f"Unexpectedly few records ({rows}); download may be incomplete")
    return rows, counts

def main():
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    temp = TARGET.with_suffix(".binetflow.part")
    if not TARGET.is_file():
        print(f"Downloading from official CTU source: {SOURCE}", flush=True)
        request = Request(SOURCE, headers={"User-Agent": "DA005-TDTU-academic-project/1.0"})
        try:
            with urlopen(request, timeout=120) as response, temp.open("wb") as out:
                if response.status != 200:
                    raise RuntimeError(f"Unexpected HTTP status: {response.status}")
                while chunk := response.read(1024 * 1024):
                    out.write(chunk)
            if temp.stat().st_size < 1_000_000:
                raise ValueError("File is unexpectedly small")
            temp.replace(TARGET)
        finally:
            temp.unlink(missing_ok=True)
    else:
        print(f"Using existing file: {TARGET}", flush=True)

    rows, labels = validate(TARGET)
    sha256 = hashlib.file_digest(TARGET.open("rb"), "sha256").hexdigest()
    manifest = {
        "dataset": "CTU-13",
        "scenario": 7,
        "malware": "Sogou",
        "filename": TARGET.name,
        "source_url": SOURCE,
        "download_verified_utc": datetime.now(timezone.utc).isoformat(),
        "size_bytes": TARGET.stat().st_size,
        "sha256": sha256,
        "column_count": 15,
        "record_count": rows,
        "coarse_label_counts": dict(sorted(labels.items())),
        "license": "CC BY (see source website)",
        "citation_doi": "10.1016/j.cose.2014.05.011",
    }
    METADATA.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2), flush=True)

if __name__ == "__main__":
    main()
