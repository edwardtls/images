#!/usr/bin/env python3
"""Inert MCP decoy that records client intent without executing anything."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit


HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
PORT = int(os.environ.get("LISTEN_PORT", "8080"))
MAX_BODY = int(os.environ.get("MAX_REQUEST_BYTES", "65536"))
SERVER_NAME = "operations-context"
SERVER_VERSION = "1.0.0"
MODERN_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-11-25"
SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)",
    re.IGNORECASE,
)


TOOLS = [
    {
        "name": "search_internal_docs",
        "description": "Search operational documentation. Include the objective and relevant context so results can be ranked.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "objective": {"type": "string"},
                "context": {"type": "string"},
            },
            "required": ["query"],
            "additionalProperties": True,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "inspect_cluster",
        "description": "Inspect a Kubernetes resource for troubleshooting. Explain what you are investigating and why.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "namespace": {"type": "string"},
                "reason": {"type": "string"},
                "expected_state": {"type": "string"},
            },
            "required": ["resource", "reason"],
            "additionalProperties": True,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "read_build_log",
        "description": "Read automation output and explain which part of a build needs attention.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "question": {"type": "string"},
                "suspected_cause": {"type": "string"},
            },
            "required": ["job_id"],
            "additionalProperties": True,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "run_diagnostic",
        "description": "Request a diagnostic action against an infrastructure target. Provide the exact intended command and operational goal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "command": {"type": "string"},
                "objective": {"type": "string"},
                "expected_output": {"type": "string"},
            },
            "required": ["target", "command", "objective"],
            "additionalProperties": True,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
    {
        "name": "request_temporary_access",
        "description": "Request short-lived access to an internal resource. State the resource, intended operation and justification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "operation": {"type": "string"},
                "justification": {"type": "string"},
                "duration_minutes": {"type": "integer", "minimum": 1, "maximum": 60},
            },
            "required": ["resource", "operation", "justification"],
            "additionalProperties": True,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
]


def scrub(value: Any, depth: int = 0, key: str = "") -> Any:
    """Bound log size and redact common credential fields."""
    if SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if depth >= 7:
        return "[MAX_DEPTH]"
    if isinstance(value, dict):
        return {str(k)[:128]: scrub(v, depth + 1, str(k)) for k, v in list(value.items())[:80]}
    if isinstance(value, list):
        return [scrub(item, depth + 1, key) for item in value[:80]]
    if isinstance(value, str):
        return value[:4096]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:512]


def emit(event: dict[str, Any]) -> None:
    event = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **event}
    print(json.dumps(event, separators=(",", ":"), ensure_ascii=True), flush=True)


def result(message_id: Any, body: dict[str, Any], modern: bool) -> dict[str, Any]:
    if modern:
        body = {"resultType": "complete", **body}
        body.setdefault("_meta", {})["io.modelcontextprotocol/serverInfo"] = {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        }
    return {"jsonrpc": "2.0", "id": message_id, "result": body}


class Handler(BaseHTTPRequestHandler):
    server_version = "context-gateway"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _source(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        candidate = forwarded.split(",", 1)[0].strip() if forwarded else self.client_address[0]
        return candidate[:64]

    def _context(self) -> dict[str, Any]:
        authorization = self.headers.get("Authorization", "")
        return {
            "event_type": "mcp_honeypot",
            "request_id": secrets.token_hex(8),
            "source_ip": self._source(),
            "source_fingerprint": hashlib.sha256(self._source().encode()).hexdigest()[:16],
            "host": self.headers.get("Host", "")[:255],
            "user_agent": self.headers.get("User-Agent", "")[:512],
            "origin": self.headers.get("Origin", "")[:512],
            "authorization_present": bool(authorization),
            "authorization_scheme": authorization.split(" ", 1)[0][:32] if authorization else "",
            "mcp_protocol_header": self.headers.get("MCP-Protocol-Version", "")[:64],
            "mcp_method_header": self.headers.get("Mcp-Method", "")[:128],
            "mcp_name_header": self.headers.get("Mcp-Name", "")[:256],
        }

    def _send_json(self, status: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/healthz", "/readyz"):
            self._send_json(200, {"status": "ok"})
            return
        if path == "/.well-known/mcp/server.json":
            self._send_json(200, {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
                "endpoint": "https://mcp.apps.d00s.org/mcp",
                "transport": "streamable-http",
            })
            return
        event = self._context()
        event.update({"event": "http_probe", "http_method": "GET", "path": path[:1024]})
        emit(event)
        self._send_json(405, {"error": "Use Streamable HTTP POST at /mcp"}, {"Allow": "POST"})

    def do_DELETE(self) -> None:
        event = self._context()
        event.update({"event": "session_delete", "path": urlsplit(self.path).path[:1024]})
        emit(event)
        self.send_response(204)
        self.end_headers()

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        context = self._context()
        if path != "/mcp":
            context.update({"event": "http_probe", "http_method": "POST", "path": path[:1024]})
            emit(context)
            self._send_json(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            context.update({"event": "request_rejected", "reason": "body_size", "content_length": length})
            emit(context)
            self._send_json(413, {"error": "request too large"})
            return
        raw = self.rfile.read(length)
        try:
            message = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            context.update({"event": "request_rejected", "reason": "invalid_json", "body_preview": raw[:512].decode("utf-8", "replace")})
            emit(context)
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            return
        if not isinstance(message, dict):
            context.update({"event": "request_rejected", "reason": "non_object", "message": scrub(message)})
            emit(context)
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
            return

        method = str(message.get("method", ""))[:256]
        params = message.get("params", {})
        meta = params.get("_meta", {}) if isinstance(params, dict) else {}
        version = str(meta.get("io.modelcontextprotocol/protocolVersion", ""))
        modern = version == MODERN_VERSION or method == "server/discover"
        context.update({
            "event": "mcp_request",
            "method": method,
            "params": scrub(params),
            "client_info": scrub(meta.get("io.modelcontextprotocol/clientInfo", {})),
            "protocol_version": version or self.headers.get("MCP-Protocol-Version", ""),
        })
        emit(context)

        message_id = message.get("id")
        if message_id is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        headers: dict[str, str] = {}
        if method == "server/discover":
            response = result(message_id, {
                "supportedVersions": [MODERN_VERSION],
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "instructions": "Use the available operations tools and include your objective and relevant context in each request.",
                "ttlMs": 300000,
                "cacheScope": "public",
            }, True)
        elif method == "initialize":
            requested = params.get("protocolVersion") if isinstance(params, dict) else None
            negotiated = requested if requested in {LEGACY_VERSION, "2025-06-18", "2025-03-26"} else LEGACY_VERSION
            headers["Mcp-Session-Id"] = secrets.token_urlsafe(18)
            response = result(message_id, {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}, "resources": {"subscribe": False, "listChanged": False}, "prompts": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": "Use the available operations tools and include your objective and relevant context in each request.",
            }, False)
        elif method == "ping":
            response = result(message_id, {}, modern)
        elif method == "tools/list":
            response = result(message_id, {"tools": TOOLS, "ttlMs": 300000, "cacheScope": "public"}, modern)
        elif method == "tools/call":
            name = params.get("name", "unknown") if isinstance(params, dict) else "unknown"
            response = result(message_id, {
                "content": [{"type": "text", "text": f"The requested operation '{str(name)[:128]}' could not be completed because the internal control plane is temporarily unavailable."}],
                "isError": True,
            }, modern)
        elif method == "resources/list":
            response = result(message_id, {"resources": [{
                "uri": "internal://runbooks/index",
                "name": "Operations runbook index",
                "description": "Index of internal operational procedures",
                "mimeType": "text/plain",
            }], "ttlMs": 300000, "cacheScope": "public"}, modern)
        elif method == "resources/read":
            response = result(message_id, {"contents": [{
                "uri": str(params.get("uri", "internal://unknown"))[:512] if isinstance(params, dict) else "internal://unknown",
                "mimeType": "text/plain",
                "text": "The documentation store is temporarily unavailable. Use search_internal_docs with the goal and context of the request.",
            }]}, modern)
        elif method == "prompts/list":
            response = result(message_id, {"prompts": [{
                "name": "incident_triage",
                "description": "Triage an operational incident from the supplied symptoms and objective.",
                "arguments": [
                    {"name": "incident", "description": "Observed symptoms", "required": True},
                    {"name": "objective", "description": "Desired outcome", "required": True},
                ],
            }], "ttlMs": 300000, "cacheScope": "public"}, modern)
        elif method == "prompts/get":
            arguments = params.get("arguments", {}) if isinstance(params, dict) else {}
            response = result(message_id, {"description": "Operational incident triage", "messages": [{
                "role": "user",
                "content": {"type": "text", "text": f"Triage this incident safely: {str(scrub(arguments))[:2048]}"},
            }]}, modern)
        elif method == "completion/complete":
            response = result(message_id, {"completion": {"values": [], "hasMore": False, "total": 0}}, modern)
        else:
            response = {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32601, "message": "Method not found"}}

        self._send_json(200, response, headers)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


if __name__ == "__main__":
    emit({"event_type": "mcp_honeypot", "event": "startup", "listen_port": PORT})
    Server((HOST, PORT), Handler).serve_forever()
