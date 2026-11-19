"""Write operator-assisted VMware stage telemetry directly as private UTF-8 JSONL.

Wraps the existing tightly scoped run_vmware_stepwise CLI, not a new network
executor. This removes PowerShell encoding/pipe ambiguity and lets a local
browser follow complete flushed lines. Dry-run remains the default.
"""
from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

import run_hostonly_benign_traffic as stimulus
import run_vmware_stepwise as stepwise


def run_to_file(*, jsonl_file: Path, cli_args: list[str]) -> int:
    """Create a new private file and run ONLY the existing safe CLI into it.

    Fails before the CLI runs if output is relative, inside Git, a symlink,
    an existing file, or not under an existing private evidence directory.
    """
    if not isinstance(jsonl_file, Path) or jsonl_file.suffix.lower() != ".jsonl":
        raise ValueError("Progress file must have .jsonl extension")
    if not jsonl_file.is_absolute() or jsonl_file.is_symlink():
        raise ValueError("Progress file must be absolute, not a symlink")
    folder = stimulus._private_dir(jsonl_file.parent)
    destination = folder / jsonl_file.name
    if destination.is_relative_to(ROOT) or destination.exists():
        raise ValueError("Progress file must be private and must not already exist")

    # O_EXCL prevents clobbering old evidence, following a final-component
    # symlink or attaching this run to an unrelated capture. 0600 on POSIX;
    # Windows inherits ACL restrictions from the private parent folder.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(destination, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n", buffering=1) as stream:
        try:
            # The underlying CLI validates all fixed scenario, CIDR, SSH,
            # model, count and operator-consent arguments. No shell involved.
            with contextlib.redirect_stdout(stream):
                return stepwise.main([*cli_args, "--progress-jsonl"])
        finally:
            stream.flush()
            os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsonl-file", type=Path, required=True,
                        help="New absolute .jsonl path outside Git, in private evidence folder")
    options, cli_args = parser.parse_known_args(argv)
    if any(arg == "--jsonl-file" for arg in cli_args):
        parser.error("Duplicate --jsonl-file option")
    try:
        code = run_to_file(jsonl_file=options.jsonl_file, cli_args=cli_args)
    except (ValueError, OSError, TypeError):
        print("DA005 private JSONL writer refused; verify an unused output path and local evidence permissions.",
              file=sys.stderr)
        return 1
    if code == 0:
        print("DA005 JSONL completed in local private file. Use /vmware-progress to view stages.")
    else:
        print("DA005 JSONL run refused or failed; inspect the local private status file.",
              file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
