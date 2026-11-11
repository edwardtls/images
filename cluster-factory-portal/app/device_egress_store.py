"""Durable history of device routing: usage samples and route switches.

Atlantis (device-egress) is the source of truth for the live counters. Every
security-collector run stores one sample per device with its cumulative totals
and the growth since the previous sample, so monthly or daily usage can be
summed later. Switches made in the portal are recorded with the
administrator; a route change seen by the collector without one is recorded as
"observed".
"""

from __future__ import annotations

import datetime as dt
from zoneinfo import ZoneInfo

from psycopg.types.json import Jsonb

from . import device_egress, security_store

RETENTION = "5 years"
SCHEMA = """
CREATE TABLE IF NOT EXISTS device_egress_samples (
  sampled_at timestamptz NOT NULL,
  device_id text NOT NULL,
  device_name text NOT NULL,
  route text NOT NULL,
  total_up bigint NOT NULL,
  total_down bigint NOT NULL,
  up_bytes bigint NOT NULL,
  down_bytes bigint NOT NULL,
  session_started_at text,
  PRIMARY KEY (device_id, sampled_at)
);
CREATE INDEX IF NOT EXISTS device_egress_samples_time_idx ON device_egress_samples (sampled_at DESC);
CREATE TABLE IF NOT EXISTS device_egress_events (
  id bigserial PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  device_id text NOT NULL,
  device_name text NOT NULL DEFAULT '',
  route text NOT NULL,
  actor text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS device_egress_events_time_idx ON device_egress_events (occurred_at DESC);
"""


def _last_route(connection, device_id: str) -> str | None:
    row = connection.execute(
        "SELECT route FROM device_egress_events WHERE device_id=%s ORDER BY occurred_at DESC, id DESC LIMIT 1",
        (device_id,)).fetchone()
    return row[0] if row else None


def record_switch(device: dict, route: str, actor: str) -> None:
    with security_store._connect() as connection:
        connection.execute(SCHEMA)
        connection.execute(
            """INSERT INTO device_egress_events (device_id, device_name, route, actor, details)
               VALUES (%s,%s,%s,%s,%s)""",
            (device["id"], device.get("name", "")[:120], route, actor[:120],
             Jsonb({"usage": device.get("usage", {})})))


def collect() -> dict:
    """Store one usage sample per device; intended for the security collector."""
    state = device_egress.status()
    now = dt.datetime.now(dt.timezone.utc)
    stored = 0
    with security_store._connect() as connection:
        connection.execute(SCHEMA)
        for device in state["devices"]:
            usage = device.get("usage") or {}
            total = usage.get("total") or {"up": 0, "down": 0}
            previous = connection.execute(
                """SELECT total_up,total_down FROM device_egress_samples WHERE device_id=%s
                   ORDER BY sampled_at DESC LIMIT 1""", (device["id"],)).fetchone()
            if previous is None and device["route"] != "us" and not (total["up"] or total["down"]):
                continue  # Never used the US path: nothing to record yet.
            up = total["up"] - previous[0] if previous and total["up"] >= previous[0] else total["up"]
            down = total["down"] - previous[1] if previous and total["down"] >= previous[1] else total["down"]
            session = usage.get("session") or {}
            connection.execute(
                """INSERT INTO device_egress_samples (sampled_at, device_id, device_name, route, total_up,
                     total_down, up_bytes, down_bytes, session_started_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (now, device["id"], device.get("name", "")[:120], device["route"], total["up"], total["down"],
                 up, down, session.get("started_at")))
            if _last_route(connection, device["id"]) != device["route"]:
                connection.execute(
                    """INSERT INTO device_egress_events (occurred_at, device_id, device_name, route, actor)
                       VALUES (%s,%s,%s,%s,'observed')""",
                    (now, device["id"], device.get("name", "")[:120], device["route"]))
            stored += 1
        connection.execute(f"DELETE FROM device_egress_samples WHERE sampled_at < now() - interval '{RETENTION}'")
        connection.execute(f"DELETE FROM device_egress_events WHERE occurred_at < now() - interval '{RETENTION}'")
    return {"devices": stored}


def history(months: int = 12, events: int = 25) -> dict:
    with security_store._connect() as connection:
        connection.execute(SCHEMA)
        monthly = connection.execute(
            """SELECT to_char(date_trunc('month', sampled_at AT TIME ZONE 'Europe/Amsterdam'), 'YYYY-MM') AS month,
                      device_id, max(device_name), sum(up_bytes), sum(down_bytes)
               FROM device_egress_samples
               WHERE sampled_at >= date_trunc('month', now() AT TIME ZONE 'Europe/Amsterdam')
                                   AT TIME ZONE 'Europe/Amsterdam' - make_interval(months => %s)
               GROUP BY 1, 2 HAVING sum(up_bytes) + sum(down_bytes) > 0
               ORDER BY 1 DESC, 2""", (months - 1,)).fetchall()
        recent = connection.execute(
            """SELECT occurred_at, device_id, device_name, route, actor FROM device_egress_events
               ORDER BY occurred_at DESC, id DESC LIMIT %s""", (events,)).fetchall()
    zone = ZoneInfo("Europe/Amsterdam")
    return {
        "monthly": [{"month": row[0], "device_id": row[1], "device_name": row[2],
                     "up": int(row[3]), "down": int(row[4])} for row in monthly],
        "events": [{"at": row[0].astimezone(zone).strftime("%Y-%m-%d %H:%M"), "device_id": row[1],
                    "device_name": row[2], "route": row[3], "actor": row[4]} for row in recent],
    }
