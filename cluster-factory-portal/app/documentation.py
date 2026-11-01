from __future__ import annotations

import re
from typing import Any

import mistune
import yaml
from markupsafe import Markup

from . import kube


CONFIGMAP = "cluster-factory-docs"
DOC_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
DOC_FILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}\.md$")
MAX_DOCUMENT_BYTES = 262_144
_markdown = mistune.create_markdown(
    renderer=mistune.HTMLRenderer(escape=True),
    plugins=["table"],
)


class DocumentationError(RuntimeError):
    pass


def _configmap() -> dict[str, Any]:
    return kube.api("GET", kube.ns_path("configmaps", CONFIGMAP))


def _catalog(configmap: dict[str, Any]) -> list[dict[str, str]]:
    try:
        parsed = yaml.safe_load(configmap["data"]["catalog.yaml"])
        documents = parsed["documents"]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise DocumentationError("The documentation catalog is invalid") from exc
    if not isinstance(documents, list) or len(documents) > 100:
        raise DocumentationError("The documentation catalog has an invalid document list")
    result = []
    seen = set()
    required = ("id", "title", "summary", "category", "location", "file", "source")
    for item in documents:
        if not isinstance(item, dict) or any(not isinstance(item.get(key), str) for key in required):
            raise DocumentationError("A documentation catalog entry is invalid")
        entry = {key: item[key].strip() for key in required}
        parent = item.get("parent")
        if parent is not None:
            if not isinstance(parent, str) or not DOC_ID_RE.fullmatch(parent.strip()):
                raise DocumentationError("A documentation catalog parent is invalid")
            entry["parent"] = parent.strip()
        if (not DOC_ID_RE.fullmatch(entry["id"]) or not DOC_FILE_RE.fullmatch(entry["file"])
                or not all(entry[key] for key in required) or entry["id"] in seen):
            raise DocumentationError("A documentation catalog entry is unsafe or duplicated")
        seen.add(entry["id"])
        result.append(entry)
    by_id = {entry["id"]: entry for entry in result}
    for entry in result:
        parent = entry.get("parent")
        if parent and (parent == entry["id"] or parent not in by_id
                       or by_id[parent].get("parent")):
            raise DocumentationError("A documentation catalog parent is missing or nested")
    return sorted(result, key=lambda item: (item["category"].lower(), item["title"].lower()))


def catalog() -> list[dict[str, str]]:
    return _catalog(_configmap())


def document(document_id: str) -> dict[str, Any] | None:
    if not DOC_ID_RE.fullmatch(document_id):
        return None
    configmap = _configmap()
    entries = _catalog(configmap)
    entry = next((item for item in entries if item["id"] == document_id), None)
    if not entry:
        return None
    try:
        markdown = configmap["data"][entry["file"]]
    except KeyError as exc:
        raise DocumentationError("The requested document is missing from the GitOps bundle") from exc
    if not isinstance(markdown, str) or len(markdown.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise DocumentationError("The requested document is invalid or too large")
    parent_id = entry.get("parent")
    parent = next((item for item in entries if item["id"] == parent_id), None)
    children = [item for item in entries if item.get("parent") == entry["id"]]
    return {
        **entry,
        "html": Markup(_markdown(markdown)),
        "markdown": markdown,
        "parent_document": parent,
        "children": children,
    }
