"""Synthetic iproute2 policy rules; no VM, sockets or network activity."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_linux_guest_policy_rules.py"


def _default_rules():
    v4 = [{"priority": p, "src": "all", "table": t} for p, t in
          ((0, "local"), (32766, "main"), (32767, "default"))]
    v6 = [{"priority": p, "src": "all", "table": t} for p, t in
          ((0, "local"), (32766, "main"))]
    return v4, v6


def _run(tmp_path, v4, v6, *, tamper=None):
    args = [sys.executable, str(SCRIPT)]
    for role, rules in (("rules-v4", v4), ("rules-v6", v6)):
        path = tmp_path / (role + ".json")
        raw = json.dumps(rules).encode("utf-8")
        path.write_bytes(raw)
        args.extend(["--" + role, str(path), "--expected-" + role + "-sha256",
                     hashlib.sha256(raw).hexdigest()])
    if tamper:
        tamper(args, tmp_path)
    return subprocess.run(args, capture_output=True, text=True)


def test_kernel_default_rules_pass_without_isolation_claim(tmp_path):
    result = _run(tmp_path, *_default_rules())
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["policy_rules_snapshot_passed"] is True
    assert report["other_routing_tables_checked"] is False
    assert report["vmware_hostonly_isolation_verified"] is False
    assert report["traffic_authorized"] is False
    assert report["network_activity_performed"] is False
    assert str(tmp_path) not in result.stdout


@pytest.mark.parametrize("change", [
    "extra_rule", "missing_main", "duplicate_priority", "wrong_table",
    "source_selector", "destination_selector", "fwmark", "goto", "suppressor",
    "non_integer_priority", "bool_priority", "wrong_ipv6_table", "missing_ipv6_main",
    "extra_ipv6_rule", "unknown_field", "empty_v4",
])
def test_nondefault_policy_rules_fail_closed(tmp_path, change):
    v4, v6 = _default_rules()
    if change == "extra_rule":
        v4.append({"priority": 100, "src": "all", "table": "100"})
    elif change == "missing_main":
        v4.pop(1)
    elif change == "duplicate_priority":
        v4[2]["priority"] = 32766
    elif change == "wrong_table":
        v4[1]["table"] = "100"
    elif change == "source_selector":
        v4[1]["src"] = "192.168.56.0/24"
    elif change == "destination_selector":
        v4[1]["dst"] = "0.0.0.0/0"
    elif change == "fwmark":
        v4[1]["fwmark"] = "0x1"
    elif change == "goto":
        v4[1]["goto"] = 32767
    elif change == "suppressor":
        v4[1]["suppress_prefixlen"] = 0
    elif change == "non_integer_priority":
        v4[1]["priority"] = "32766"
    elif change == "bool_priority":
        v4[1]["priority"] = True
    elif change == "wrong_ipv6_table":
        v6[1]["table"] = "default"
    elif change == "missing_ipv6_main":
        v6.pop()
    elif change == "extra_ipv6_rule":
        v6.append({"priority": 100, "src": "all", "table": "main"})
    elif change == "unknown_field":
        v4[0]["protocol"] = "boot"
    elif change == "empty_v4":
        v4.clear()
    result = _run(tmp_path, v4, v6)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_numeric_kernel_tables_and_optional_ipv6_default_rule(tmp_path):
    v4, v6 = _default_rules()
    for rules in (v4, v6):
        for rule in rules:
            rule["table"] = {"local": 255, "main": 254, "default": 253}[rule["table"]]
    v6.append({"priority": 32767, "src": "all", "table": 253})
    result = _run(tmp_path, v4, v6)
    assert result.returncode == 0, result.stderr


def test_tampered_pinned_bytes_fail(tmp_path):
    def tamper(args, root):
        (root / "rules-v4.json").write_bytes(b"[]")
    result = _run(tmp_path, *_default_rules(), tamper=tamper)
    assert result.returncode == 1
    assert result.stdout == ""


def test_duplicate_json_keys_fail(tmp_path):
    def tamper(args, root):
        raw = b'[{"priority":0,"priority":32766,"src":"all","table":"local"}]'
        (root / "rules-v4.json").write_bytes(raw)
        args[args.index("--expected-rules-v4-sha256") + 1] = hashlib.sha256(raw).hexdigest()
    result = _run(tmp_path, *_default_rules(), tamper=tamper)
    assert result.returncode == 1
    assert result.stdout == ""
