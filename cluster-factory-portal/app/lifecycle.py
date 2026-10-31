from __future__ import annotations

import datetime as dt
from typing import Any


def _time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _ttl(value: Any) -> dt.timedelta | None:
    if not isinstance(value, str) or len(value) < 2:
        return None
    try:
        amount = int(value[:-1])
    except ValueError:
        return None
    if amount < 1:
        return None
    return {"h": dt.timedelta(hours=amount),
            "d": dt.timedelta(days=amount),
            "w": dt.timedelta(weeks=amount)}.get(value[-1])


def lifecycle_history(audits: list[dict], now: dt.datetime | None = None) -> list[dict]:
    """Correlate create and delete audits into human-readable cluster lifecycles."""
    now = now or dt.datetime.now(dt.timezone.utc)
    operations = [item for item in audits if item.get("action") in {"create", "delete"}]
    operations.sort(key=lambda item: str(item.get("submitted_at", "")))
    result = []
    for index, create in enumerate(operations):
        if create.get("action") != "create":
            continue
        profile = str(create.get("profile", "unknown"))
        submitted = _time(create.get("submitted_at"))
        completed = _time(create.get("completed_at"))
        next_create = next((item for item in operations[index + 1:]
                            if item.get("action") == "create" and item.get("profile") == profile), None)
        next_create_at = _time(next_create.get("submitted_at")) if next_create else None
        deletion = next((item for item in operations[index + 1:]
                         if item.get("action") == "delete" and item.get("profile") == profile
                         and (not next_create_at or (_time(item.get("submitted_at")) or now) < next_create_at)), None)
        ttl_value = create.get("request", {}).get("lifecycle", {}).get("ttl", "—")
        ttl_delta = _ttl(ttl_value)
        expires = completed + ttl_delta if completed and ttl_delta and create.get("status") == "succeeded" else None
        create_status = str(create.get("status", "unknown"))
        if create_status != "succeeded":
            state = "Build failed" if create_status == "failed" else f"Build {create_status}"
            state_class = "failed" if create_status == "failed" else "pending"
        elif deletion:
            delete_status = str(deletion.get("status", "unknown"))
            deleted = _time(deletion.get("completed_at")) or _time(deletion.get("submitted_at"))
            if delete_status == "succeeded" and expires and deleted:
                delay = deleted - expires
                if delay > dt.timedelta(minutes=15):
                    state, state_class = "Decommissioned late", "pending"
                elif delay < -dt.timedelta(minutes=15):
                    state, state_class = "Decommissioned early", "complete"
                else:
                    state, state_class = "Decommissioned on time", "complete"
            else:
                state = {"succeeded": "Decommissioned", "failed": "Cleanup failed"}.get(
                    delete_status, f"Deletion {delete_status}")
                state_class = "complete" if delete_status == "succeeded" else "failed"
        elif expires and expires <= now:
            state = "Expiry overdue"
            state_class = "failed"
        else:
            state = "Active"
            state_class = "active"
        result.append({
            "profile": profile,
            "owner": create.get("owner") or "unknown",
            "job_id": create.get("job_id") or "—",
            "submitted_at": create.get("submitted_at") or "",
            "completed_at": create.get("completed_at") or "",
            "ttl": ttl_value,
            "expires_at": expires.isoformat() if expires else "",
            "state": state,
            "state_class": state_class,
            "delete_job_id": deletion.get("job_id") if deletion else "",
            "deleted_at": deletion.get("completed_at") if deletion else "",
            "delete_owner": deletion.get("owner") if deletion else "",
            "retain_data": bool(deletion and deletion.get("request", {}).get("retain_data", False)),
            "request": create.get("request", {}),
            "submitted": submitted,
        })
    result.sort(key=lambda item: item["submitted"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc), reverse=True)
    for item in result:
        item.pop("submitted", None)
    return result
