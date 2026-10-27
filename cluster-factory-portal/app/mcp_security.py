"""Read bounded, sanitized MCP honeypot events from Loki."""

from __future__ import annotations

import datetime as dt
import json
import os
import ssl
import urllib.parse
import urllib.request
from collections import Counter
from zoneinfo import ZoneInfo


LOKI_QUERY = '{k8s_namespace_name="mcp-honeypot"} | json | event="mcp_request"'
WINDOWS = {"3h": 3 * 3600, "24h": 24 * 3600, "3d": 3 * 86400,
           "7d": 7 * 86400, "all": 30 * 86400}
MAX_EVENTS = 500
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SENSITIVE_PARTS = ("password", "passwd", "secret", "token", "credential",
                   "authorization", "cookie", "private_key", "api_key")


def _bounds(window: str) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    if window == "today":
        local = now.astimezone(ZoneInfo("Europe/Amsterdam"))
        start = local.replace(hour=0, minute=0, second=0, microsecond=0)
        return start.astimezone(dt.timezone.utc), now
    if window not in WINDOWS:
        raise ValueError("invalid MCP security time window")
    return now - dt.timedelta(seconds=WINDOWS[window]), now


def _safe(value, *, key: str = "", depth: int = 0):
    """Defensively redact Loki content again before rendering it."""
    normalized = key.lower().replace("-", "_")
    if any(part in normalized for part in SENSITIVE_PARTS):
        return "[REDACTED]"
    if depth >= 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {str(k)[:80]: _safe(v, key=str(k), depth=depth + 1)
                for k, v in list(value.items())[:50]}
    if isinstance(value, list):
        return [_safe(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, str):
        return value[:2000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:2000]


def _query(window: str) -> list[dict]:
    start, end = _bounds(window)
    base = os.getenv("LOKI_QUERY_URL", "https://loki.d00s.org/loki/api/v1/query_range")
    target = urllib.parse.urlsplit(base)
    if target.scheme != "https" or target.hostname != "loki.d00s.org":
        raise RuntimeError("invalid Loki query endpoint")
    query = urllib.parse.urlencode({
        "query": LOKI_QUERY,
        "start": str(int(start.timestamp() * 1_000_000_000)),
        "end": str(int(end.timestamp() * 1_000_000_000)),
        "direction": "backward",
        "limit": str(MAX_EVENTS),
    })
    request = urllib.request.Request(f"{base}?{query}", headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10, context=ssl.create_default_context()) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError("Loki response exceeded the portal safety limit")
    payload = json.loads(raw)
    if payload.get("status") != "success":
        raise RuntimeError("Loki did not return a successful response")
    values = []
    for stream in payload.get("data", {}).get("result", []):
        values.extend(stream.get("values", []))
    values.sort(key=lambda item: int(item[0]), reverse=True)
    events = []
    for timestamp_ns, line in values[:MAX_EVENTS]:
        try:
            event = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            continue
        if event.get("event") != "mcp_request":
            continue
        params = _safe(event.get("params") or {})
        client = _safe(event.get("client_info") or {})
        tool = params.get("name", "") if isinstance(params, dict) else ""
        events.append({
            "timestamp": str(event.get("timestamp") or dt.datetime.fromtimestamp(
                int(timestamp_ns) / 1_000_000_000, tz=dt.timezone.utc).isoformat()),
            "source_ip": str(event.get("source_ip") or "—")[:64],
            "source_fingerprint": str(event.get("source_fingerprint") or "—")[:80],
            "user_agent": str(event.get("user_agent") or "—")[:300],
            "origin": str(event.get("origin") or "—")[:300],
            "method": str(event.get("method") or "—")[:120],
            "tool": str(tool or "")[:120],
            "client": client,
            "client_name": str(client.get("name") or "—")[:120] if isinstance(client, dict) else "—",
            "client_version": str(client.get("version") or "")[:80] if isinstance(client, dict) else "",
            "protocol": str(event.get("protocol_version") or event.get("mcp_protocol_header") or "—")[:80],
            "authorization_present": bool(event.get("authorization_present")),
            "authorization_scheme": str(event.get("authorization_scheme") or "")[:40],
            "params": params,
            "params_json": json.dumps(params, ensure_ascii=True, indent=2, sort_keys=True)[:12000],
        })
    return events


def status(window: str) -> dict:
    events = _query(window)
    methods = Counter(event["method"] for event in events)
    tools = Counter(event["tool"] for event in events if event["tool"])
    clients = Counter(event["client_name"] for event in events)
    return {
        "events": events,
        "total": len(events),
        "unique_sources": len({event["source_fingerprint"] for event in events}),
        "tool_calls": methods.get("tools/call", 0),
        "authenticated": sum(1 for event in events if event["authorization_present"]),
        "methods": [{"name": name, "count": count} for name, count in methods.most_common(8)],
        "tools": [{"name": name, "count": count} for name, count in tools.most_common(8)],
        "clients": [{"name": name, "count": count} for name, count in clients.most_common(8)],
        "truncated": len(events) >= MAX_EVENTS,
    }
