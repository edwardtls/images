"""The vulnerability report that the Atlantis scan writes twice a day.

The security collector copies each new report into the security database in
one transaction, and the pages read it from there.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import threading

from psycopg.types.json import Jsonb

from . import edge_security, security_store

KINDS = {"system", "vulnerability", "image"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,120}$")
EXPORT_SECONDS = 150  # within the collector job's 240 s deadline

SCHEMA = """
CREATE TABLE IF NOT EXISTS vuln_documents (
  kind text NOT NULL,
  id text NOT NULL,
  payload jsonb NOT NULL,
  PRIMARY KEY (kind, id)
);
"""


class NotFound(LookupError):
    pass


def _imported(connection) -> str | None:
    row = connection.execute(
        "SELECT payload->>'generated_at' FROM security_state WHERE name='vulnerabilities'").fetchone()
    return row[0] if row else None


def _export():
    """Yield (kind, id, document) from the dispatcher, then check the closing line."""
    process = subprocess.Popen(edge_security.ssh_command("vulns", "export"), stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
    timer = threading.Timer(EXPORT_SECONDS, process.kill)
    timer.start()
    try:
        generated, finished = None, False
        for line in process.stdout:
            item = json.loads(line)
            kind = item.get("kind")
            if kind == "end":
                if not generated or item.get("generated_at") != generated:
                    raise RuntimeError("the report changed or failed while it was exported")
                finished = True
                break
            if kind == "overview" and generated is None:
                generated = item["document"]["generated_at"]
                yield kind, "", item["document"]
            elif kind in KINDS and generated and IDENTIFIER.fullmatch(str(item.get("id", ""))):
                yield kind, item["id"], item["document"]
            else:
                raise RuntimeError(f"unexpected export line: {str(kind)[:40]}")
        if not finished:
            raise RuntimeError("the report export ended early")
    finally:
        timer.cancel()
        process.kill()
        process.wait()


def collect() -> dict:
    """Import the latest report if it is newer than the one in the database."""
    latest = edge_security._command("vulns", "latest").get("generated_at")
    with security_store._connect() as connection:
        connection.execute(security_store.SCHEMA)
        connection.execute(SCHEMA)
        if not latest or latest == _imported(connection):
            return {"vulnerabilities": "unchanged"}
        connection.execute("DELETE FROM vuln_documents")
        imported, generated = 0, None
        with connection.cursor().copy("COPY vuln_documents (kind, id, payload) FROM STDIN") as copy:
            for kind, identifier, document in _export():
                if kind == "overview":
                    generated = document["generated_at"]
                copy.write_row((kind, identifier, json.dumps(document, separators=(",", ":"))))
                imported += 1
        connection.execute(
            """INSERT INTO security_state(name,observed_at,payload) VALUES('vulnerabilities',now(),%s)
               ON CONFLICT(name) DO UPDATE SET observed_at=EXCLUDED.observed_at, payload=EXCLUDED.payload""",
            (Jsonb({"generated_at": generated, "documents": imported}),))
    return {"vulnerabilities": imported}


def status() -> dict:
    with security_store._connect() as connection:
        row = connection.execute(
            "SELECT payload, observed_at FROM security_state WHERE name='vulnerabilities'").fetchone()
    if not row:
        raise NotFound("no report imported yet")
    imported_at = row[1].astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return {"generated_at": row[0].get("generated_at"), "imported_at": imported_at}


def _document(kind: str, identifier: str) -> str:
    with security_store._connect() as connection:
        row = connection.execute("SELECT payload::text FROM vuln_documents WHERE kind=%s AND id=%s",
                                 (kind, identifier)).fetchone()
    if not row:
        raise NotFound(f"{kind} not found")
    return row[0]


def overview() -> str:
    return _document("overview", "")


def detail(kind: str, identifier: str) -> str:
    if kind not in KINDS or not IDENTIFIER.fullmatch(identifier):
        raise ValueError("invalid vulnerability report identifier")
    return _document(kind, identifier)
