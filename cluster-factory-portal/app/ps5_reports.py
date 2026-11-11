"""Read bounded PS5 network reports through the forced Atlantis command."""

from __future__ import annotations

import json
import re
import subprocess

from . import documentation, edge_security

REPORT_DATE = re.compile(r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]$")
MAX_REPORT_BYTES = 262_144


class NotFound(RuntimeError):
    pass


def report(requested: str = "latest") -> dict:
    if requested != "latest" and not REPORT_DATE.fullmatch(requested):
        raise ValueError("invalid report date")
    result = subprocess.run(
        edge_security.ssh_command("ps5", "report", requested),
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    document = json.loads(result.stdout)
    if document == {"error": "not_found"}:
        raise NotFound("report not found")
    if (not isinstance(document, dict)
            or not REPORT_DATE.fullmatch(str(document.get("date", "")))
            or not isinstance(document.get("markdown"), str)
            or len(document["markdown"].encode("utf-8")) > MAX_REPORT_BYTES):
        raise RuntimeError("Atlantis returned an invalid PS5 report")
    return {
        "date": document["date"],
        "html": documentation.render_markdown(document["markdown"]),
    }
