"""Read and administer the edge CrowdSec mesh through a forced SSH command."""

from __future__ import annotations

import json
import os
import subprocess

VALID_WINDOWS = {"3h", "today", "24h", "3d", "7d", "all"}


def _command(*parts: str) -> dict:
    command = [
        "ssh", "-F", "/dev/null", "-p", os.getenv("EDGE_SSH_PORT", "2200"),
        "-i", os.getenv("EDGE_SSH_KEY", "/ssh/id_ed25519"),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=5",
        "-o", f"UserKnownHostsFile={os.getenv('EDGE_SSH_KNOWN_HOSTS', '/ssh-config/known_hosts')}",
        os.getenv("EDGE_SSH_TARGET", "edward@192.168.31.254"), *parts,
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=20)
    document = json.loads(result.stdout)
    if not isinstance(document, dict):
        raise RuntimeError("edge security command returned an invalid response")
    return document


def status(window: str = "3h") -> dict:
    if window not in VALID_WINDOWS:
        raise ValueError("invalid security time window")
    return _command("security", "status", window)


def delete(address: str) -> dict:
    return _command("security", "delete", address)
