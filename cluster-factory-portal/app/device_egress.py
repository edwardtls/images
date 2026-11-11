"""Switch catalogued home devices between KPN and the US path on Atlantis.

The device catalog and every routing/firewall rule live on Atlantis
(device-egress); the portal only sends a catalogue id and on/off through the
forced-command SSH dispatcher.
"""

from __future__ import annotations

import json
import re
import subprocess

from . import edge_security

DEVICE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")


def _run(*parts: str) -> dict:
    result = subprocess.run(edge_security.ssh_command("egress", *parts), check=True,
                            capture_output=True, text=True, timeout=60)
    document = json.loads(result.stdout)
    if not isinstance(document, dict) or not isinstance(document.get("devices"), list):
        raise RuntimeError("device routing returned an invalid response")
    return document


def status() -> dict:
    return _run("status")


def switch(device_id: str, enabled: bool) -> dict:
    if not DEVICE_ID.fullmatch(device_id):
        raise ValueError("invalid device id")
    return _run("set", device_id, "on" if enabled else "off")
