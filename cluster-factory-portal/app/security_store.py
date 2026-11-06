"""Durable, indexed security telemetry for the Factory security views."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from collections import Counter
from zoneinfo import ZoneInfo

import psycopg
from psycopg.types.json import Jsonb

from . import edge_security, mcp_security


RETENTION = "5 years"
WINDOW_SECONDS = {"3h": 3 * 3600, "24h": 86400, "3d": 3 * 86400,
                  "7d": 7 * 86400, "all": 5 * 366 * 86400}
WINDOW_BUCKETS = {"3h": "15 minutes", "today": "1 hour", "24h": "1 hour",
                  "3d": "3 hours", "7d": "6 hours", "all": "30 days"}
MAX_VISIBLE_FINDINGS = 500
MAX_VISIBLE_MCP = 500


def _connect():
    url = os.environ.get("SECURITY_DATABASE_URL")
    if not url:
        raise RuntimeError("SECURITY_DATABASE_URL is not configured")
    return psycopg.connect(url, connect_timeout=5)


def _bounds(window: str) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    if window == "today":
        local = now.astimezone(ZoneInfo("Europe/Amsterdam"))
        start = local.replace(hour=0, minute=0, second=0, microsecond=0)
        return start.astimezone(dt.timezone.utc), now
    if window not in WINDOW_SECONDS:
        raise ValueError("invalid security time window")
    return now - dt.timedelta(seconds=WINDOW_SECONDS[window]), now


SCHEMA = """
CREATE TABLE IF NOT EXISTS edge_findings (
  event_key text PRIMARY KEY,
  event_at timestamptz NOT NULL,
  last_seen timestamptz NOT NULL DEFAULT now(),
  active boolean NOT NULL DEFAULT true,
  service text NOT NULL,
  address text NOT NULL,
  country text NOT NULL DEFAULT '',
  sensor text NOT NULL DEFAULT '',
  payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS edge_findings_time_idx ON edge_findings (event_at DESC);
CREATE INDEX IF NOT EXISTS edge_findings_service_time_idx ON edge_findings (service, event_at DESC);
CREATE INDEX IF NOT EXISTS edge_findings_country_time_idx ON edge_findings (country, event_at DESC);
CREATE INDEX IF NOT EXISTS edge_findings_active_idx ON edge_findings (active, event_at DESC);
CREATE TABLE IF NOT EXISTS mcp_findings (
  cursor text PRIMARY KEY,
  event_at timestamptz NOT NULL,
  source_fingerprint text NOT NULL DEFAULT '',
  method text NOT NULL DEFAULT '',
  tool text NOT NULL DEFAULT '',
  client_name text NOT NULL DEFAULT '',
  authorization_present boolean NOT NULL DEFAULT false,
  payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS mcp_findings_time_idx ON mcp_findings (event_at DESC);
CREATE INDEX IF NOT EXISTS mcp_findings_method_time_idx ON mcp_findings (method, event_at DESC);
CREATE TABLE IF NOT EXISTS security_state (
  name text PRIMARY KEY,
  observed_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL
);
"""


def initialize() -> None:
    with _connect() as connection:
        connection.execute(SCHEMA)


def _edge_key(item: dict) -> str:
    stable = "\0".join(str(item.get(key, "")) for key in
                       ("created_at", "ip", "scenario", "sensor", "service"))
    return hashlib.sha256(stable.encode()).hexdigest()


def collect() -> dict:
    """Collect once. Intended for the singleton Kubernetes CronJob."""
    edge = edge_security.status("all")
    # A rolling seven-day overlap makes collection idempotent while avoiding a
    # five-year Loki scan every few minutes. The deployment performs a wider
    # one-time backfill after the database is created.
    mcp_window = "all" if os.getenv("SECURITY_BACKFILL") == "1" else "7d"
    mcp_events = mcp_security.events(mcp_window, limit=5000)
    now = dt.datetime.now(dt.timezone.utc)
    with _connect() as connection:
        connection.execute(SCHEMA)
        connection.execute("UPDATE edge_findings SET active = false WHERE active")
        for item in edge.get("decisions", []):
            event_at = item.get("created_at") or now.isoformat()
            connection.execute(
                """INSERT INTO edge_findings
                   (event_key,event_at,last_seen,active,service,address,country,sensor,payload)
                   VALUES (%s,%s,%s,true,%s,%s,%s,%s,%s)
                   ON CONFLICT (event_key) DO UPDATE SET
                     last_seen=EXCLUDED.last_seen, active=true, payload=EXCLUDED.payload,
                     country=EXCLUDED.country, sensor=EXCLUDED.sensor""",
                (_edge_key(item), event_at, now, str(item.get("service") or "Unknown")[:32],
                 str(item.get("ip") or "")[:64], str(item.get("country") or "")[:8],
                 str(item.get("sensor") or "")[:120], Jsonb(item)))
        state = {"sensors": edge.get("sensors", []), "bouncers": edge.get("bouncers", []),
                 "total_active_bans": edge.get("total_active_bans", 0)}
        connection.execute(
            """INSERT INTO security_state(name,observed_at,payload) VALUES('edge',%s,%s)
               ON CONFLICT(name) DO UPDATE SET observed_at=EXCLUDED.observed_at,
                 payload=EXCLUDED.payload""", (now, Jsonb(state)))
        for event in mcp_events:
            connection.execute(
                """INSERT INTO mcp_findings
                   (cursor,event_at,source_fingerprint,method,tool,client_name,
                    authorization_present,payload)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(cursor) DO UPDATE SET payload=EXCLUDED.payload""",
                (event["cursor"], event["timestamp"], event["source_fingerprint"],
                 event["method"], event["tool"], event["client_name"],
                 event["authorization_present"], Jsonb(event)))
        connection.execute("DELETE FROM edge_findings WHERE event_at < now() - interval '5 years'")
        connection.execute("DELETE FROM mcp_findings WHERE event_at < now() - interval '5 years'")
    return {"edge": len(edge.get("decisions", [])), "mcp": len(mcp_events)}


def edge_status(window: str) -> dict:
    start, end = _bounds(window)
    bucket = WINDOW_BUCKETS[window]
    with _connect() as connection:
        total = connection.execute(
            "SELECT count(*) FROM edge_findings WHERE event_at >= %s AND event_at <= %s",
            (start, end)).fetchone()[0]
        active_total = connection.execute(
            "SELECT count(*) FROM edge_findings WHERE active").fetchone()[0]
        service_rows = connection.execute(
            """SELECT service,count(*) FROM edge_findings
               WHERE event_at >= %s AND event_at <= %s GROUP BY service""",
            (start, end)).fetchall()
        services = {row[0]: row[1] for row in service_rows}
        countries = connection.execute(
            """SELECT country,count(*) AS amount FROM edge_findings
               WHERE event_at >= %s AND event_at <= %s AND country <> ''
               GROUP BY country ORDER BY amount DESC,country LIMIT 5""", (start, end)).fetchall()
        findings = connection.execute(
            """SELECT payload,active FROM edge_findings
               WHERE event_at >= %s AND event_at <= %s
               ORDER BY event_at DESC LIMIT %s""", (start, end, MAX_VISIBLE_FINDINGS)).fetchall()
        state_row = connection.execute(
            "SELECT payload,observed_at FROM security_state WHERE name='edge'").fetchone()
        trend_rows = connection.execute(
            """WITH buckets AS (
                 SELECT generate_series(date_bin(%s::interval,%s::timestamptz,'2000-01-01'::timestamptz),
                                        %s::timestamptz,%s::interval) AS bucket
               ), counts AS (
                 SELECT date_bin(%s::interval,event_at,'2000-01-01'::timestamptz) AS bucket,
                   count(*) AS total,
                   count(*) FILTER (WHERE service='SSH') AS ssh,
                   count(*) FILTER (WHERE service='RDP') AS rdp,
                   count(*) FILTER (WHERE service='HTTP/S') AS http
                 FROM edge_findings WHERE event_at >= %s AND event_at <= %s GROUP BY 1
               ) SELECT buckets.bucket,coalesce(total,0),coalesce(ssh,0),coalesce(rdp,0),coalesce(http,0)
                 FROM buckets LEFT JOIN counts USING(bucket) ORDER BY buckets.bucket""",
            (bucket, start, end, bucket, bucket, start, end)).fetchall()
    state = state_row[0] if state_row else {}
    decisions = []
    for payload, active in findings:
        item = dict(payload); item["active"] = active; decisions.append(item)
    points = [{"timestamp": row[0].isoformat(), "total": row[1], "ssh": row[2],
               "rdp": row[3], "http": row[4]} for row in trend_rows]
    return {
        "active_bans": total, "total_active_bans": active_total,
        "ssh_bans": services.get("SSH", 0), "rdp_bans": services.get("RDP", 0),
        "http_bans": services.get("HTTP/S", 0),
        "top_countries": [{"country": row[0], "count": row[1]} for row in countries],
        "decisions": decisions, "findings_truncated": total > MAX_VISIBLE_FINDINGS,
        "sensors": state.get("sensors", []), "bouncers": state.get("bouncers", []),
        "observed_at": state_row[1].isoformat() if state_row else None,
        "trend": {"bucket_seconds": int(dt.timedelta(**_interval_kwargs(bucket)).total_seconds()),
                  "points": points, "totals": {
                      "total": sum(p["total"] for p in points),
                      "ssh": sum(p["ssh"] for p in points),
                      "rdp": sum(p["rdp"] for p in points),
                      "http": sum(p["http"] for p in points)}}}


def _interval_kwargs(value: str) -> dict:
    amount, unit = value.split()
    return {"minutes" if unit.startswith("minute") else
            "hours" if unit.startswith("hour") else "days": int(amount)}


def mcp_status(window: str) -> dict:
    start, end = _bounds(window)
    with _connect() as connection:
        rows = connection.execute(
            """SELECT payload FROM mcp_findings WHERE event_at >= %s AND event_at <= %s
               ORDER BY event_at DESC LIMIT %s""", (start, end, MAX_VISIBLE_MCP)).fetchall()
        aggregate = connection.execute(
            """SELECT count(*),count(DISTINCT source_fingerprint),
                      count(*) FILTER (WHERE method='tools/call'),
                      count(*) FILTER (WHERE authorization_present)
               FROM mcp_findings WHERE event_at >= %s AND event_at <= %s""", (start, end)).fetchone()
        methods = connection.execute(
            """SELECT method,count(*) amount FROM mcp_findings WHERE event_at >= %s AND event_at <= %s
               GROUP BY method ORDER BY amount DESC LIMIT 8""", (start, end)).fetchall()
        tools = connection.execute(
            """SELECT tool,count(*) amount FROM mcp_findings WHERE event_at >= %s AND event_at <= %s
               AND tool <> '' GROUP BY tool ORDER BY amount DESC LIMIT 8""", (start, end)).fetchall()
        clients = connection.execute(
            """SELECT client_name,count(*) amount FROM mcp_findings WHERE event_at >= %s AND event_at <= %s
               GROUP BY client_name ORDER BY amount DESC LIMIT 8""", (start, end)).fetchall()
    events = [row[0] for row in rows]
    return {"events": events, "total": aggregate[0], "unique_sources": aggregate[1],
            "tool_calls": aggregate[2], "authenticated": aggregate[3],
            "methods": [{"name": r[0], "count": r[1]} for r in methods],
            "tools": [{"name": r[0], "count": r[1]} for r in tools],
            "clients": [{"name": r[0], "count": r[1]} for r in clients],
            "truncated": aggregate[0] > MAX_VISIBLE_MCP}


def latest_mcp_cursor() -> str | None:
    with _connect() as connection:
        row = connection.execute("SELECT cursor FROM mcp_findings ORDER BY event_at DESC LIMIT 1").fetchone()
    return row[0] if row else None
