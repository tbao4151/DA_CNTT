"""UNSW download integrity regression tests; all fixtures are local and synthetic."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import download_unsw_nb15 as downloader


CSV = (
    "id,proto,service,state,dur,sbytes,dbytes,attack_cat,label\\n"
    "1,tcp,http,FIN,1,120,30,Exploits,1\\n"
).replace("\\n", "\n").encode("utf-8")


@pytest.fixture
def isolated_download(tmp_path, monkeypatch):
    monkeypatch.setattr(downloader, "OUT", tmp_path)
    monkeypatch.setattr(
        downloader, "FILES",
        {"fixture.csv": (1, hashlib.sha256(CSV).hexdigest())},
    )
    return tmp_path


def test_download_verifies_before_promoting_file(isolated_download, monkeypatch):
    def retrieve(_url, destination):
        Path(destination).write_bytes(CSV)

    monkeypatch.setattr(downloader.urllib.request, "urlretrieve", retrieve)
    downloader.main()
    assert (isolated_download / "fixture.csv").read_bytes() == CSV
    assert not (isolated_download / "fixture.csv.part").exists()
    metadata = json.loads((isolated_download / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["files"]["fixture.csv"]["records"] == 1


def test_bad_download_never_becomes_official_file(isolated_download, monkeypatch):
    def retrieve(_url, destination):
        Path(destination).write_bytes(CSV + b"tampered")

    monkeypatch.setattr(downloader.urllib.request, "urlretrieve", retrieve)
    with pytest.raises(ValueError, match="downloaded SHA256 mismatch"):
        downloader.main()
    assert not (isolated_download / "fixture.csv").exists()
    assert not (isolated_download / "fixture.csv.part").exists()
    assert not (isolated_download / "metadata.json").exists()


def test_interrupted_download_cleans_only_partial_file(isolated_download, monkeypatch):
    def retrieve(_url, destination):
        Path(destination).write_bytes(CSV[:12])
        raise OSError("simulated interrupted transfer")

    monkeypatch.setattr(downloader.urllib.request, "urlretrieve", retrieve)
    with pytest.raises(OSError, match="interrupted transfer"):
        downloader.main()
    assert not (isolated_download / "fixture.csv").exists()
    assert not (isolated_download / "fixture.csv.part").exists()


def test_existing_bad_file_is_not_silently_overwritten(isolated_download, monkeypatch):
    target = isolated_download / "fixture.csv"
    target.write_bytes(b"local data; preserve for diagnosis")

    def no_download(*_args, **_kwargs):
        raise AssertionError("existing files must not be downloaded over")

    monkeypatch.setattr(downloader.urllib.request, "urlretrieve", no_download)
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        downloader.main()
    assert target.read_bytes() == b"local data; preserve for diagnosis"
