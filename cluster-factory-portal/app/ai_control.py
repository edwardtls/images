"""Operate the normally-off Atlantis AI through the forced SSH boundary."""

from __future__ import annotations

import json
import os
import subprocess

VALID_ACTIONS = {"status", "enable", "development", "scan", "stop"}


def command(action: str) -> dict:
    if action not in VALID_ACTIONS:
        raise ValueError("invalid AI control action")
    result = subprocess.run([
        "ssh", "-F", "/dev/null", "-p", os.getenv("EDGE_SSH_PORT", "2200"),
        "-i", os.getenv("EDGE_SSH_KEY", "/ssh/id_ed25519"),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
        "-o", f"UserKnownHostsFile={os.getenv('EDGE_SSH_KNOWN_HOSTS', '/ssh-config/known_hosts')}",
        os.getenv("EDGE_SSH_TARGET", "edward@192.168.31.254"), "ai", action,
    ], check=True, capture_output=True, text=True, timeout=40)
    document = json.loads(result.stdout)
    if not isinstance(document, dict):
        raise RuntimeError("AI controller returned an invalid response")
    return document
