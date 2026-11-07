"""Read the vulnerability report that the Atlantis scan writes twice a day."""

from __future__ import annotations

import re
import threading
import time

from . import edge_security

KINDS = {"system", "vulnerability", "image"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,120}$")
CACHE_SECONDS = 30

_cache: dict[tuple[str, str], tuple[float, dict]] = {}
_lock = threading.Lock()


class NotFound(LookupError):
    pass


def _read(kind: str, identifier: str = "") -> dict:
    key = (kind, identifier)
    with _lock:
        cached = _cache.get(key)
        if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
            return cached[1]
    arguments = ("vulns", kind, identifier) if identifier else ("vulns", kind)
    document = edge_security._command(*arguments)
    if document.get("error") == "not_found":
        raise NotFound(f"{kind} not found")
    with _lock:
        if len(_cache) > 256:
            _cache.clear()
        _cache[key] = (time.monotonic(), document)
    return document


def overview() -> dict:
    return _read("overview")


def detail(kind: str, identifier: str) -> dict:
    if kind not in KINDS or not IDENTIFIER.fullmatch(identifier):
        raise ValueError("invalid vulnerability report identifier")
    return _read(kind, identifier)
