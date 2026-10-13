#!/usr/bin/env python3
"""Download and validate UNSW-NB15 standard train/test partition."""
import csv
import hashlib
import json
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/raw/unsw_nb15"
BASE = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/"
FILES = {
    "UNSW_NB15_training-set.csv": (175341, "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"),
    "UNSW_NB15_testing-set.csv": (82332, "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559")
}
REQUIRED = {"id", "proto", "service", "state", "dur", "sbytes", "dbytes", "attack_cat", "label"}

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    metadata = {"dataset": "UNSW-NB15", "variant": "official train/test partition", "official_source": "https://research.unsw.edu.au/projects/unsw-nb15-dataset", "mirror": BASE, "files": {}}
    for name, (expected_rows, expected_hash) in FILES.items():
        target = OUT / name
        if not target.exists():
            temporary = OUT / (name + ".part")
            try:
                urllib.request.urlretrieve(BASE + name, temporary)
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
        actual_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(f"{name}: SHA256 mismatch ({actual_hash}); do not use this copy")
        with target.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not REQUIRED.issubset(reader.fieldnames or []):
                raise ValueError(f"{name}: missing required columns")
            binary, categories = Counter(), Counter()
            count = 0
            for row in reader:
                count += 1
                binary[row["label"].strip()] += 1
                categories[row["attack_cat"].strip() or "Normal"] += 1
        if count != expected_rows:
            raise ValueError(f"{name}: {count} rows, expected {expected_rows}")
        if sum(binary.values()) != count or not set(binary).issubset({"0","1"}):
            raise ValueError(f"{name}: invalid binary labels")
        metadata["files"][name] = {"records": count, "sha256": actual_hash, "bytes": target.stat().st_size, "binary_labels": dict(binary), "attack_categories": dict(sorted(categories.items()))}
        print(name, count, dict(binary))
    (OUT / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Validated both files; metadata.json generated.")

if __name__ == "__main__":
    main()
