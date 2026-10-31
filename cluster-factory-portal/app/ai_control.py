"""Kubernetes-native control plane for the normally-off AI remediator."""

from __future__ import annotations

import datetime as dt
import json
import uuid

from . import kube

VALID_ACTIONS = {"status", "enable", "development", "stay", "scan", "stop"}
STATE = "d00s-ai-state"
MODEL = "d00s-ai-model"
WORKER_TEMPLATE = "d00s-ai-remediator"
AI_SELECTOR = "app.kubernetes.io/name=d00s-ai-remediator"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _state() -> dict:
    try:
        raw = kube.api("GET", kube.ns_path("configmaps", STATE)).get("data", {}).get("state.json", "{}")
        return json.loads(raw)
    except (kube.KubeError, json.JSONDecodeError):
        return {"mode": "off", "deadline": None, "extensions": 0, "last_run": None}


def _write_state(values: dict) -> dict:
    current = _state()
    current.update(values)
    kube.api("PATCH", kube.ns_path("configmaps", STATE),
             {"data": {"state.json": json.dumps(current, sort_keys=True)}},
             content_type="application/merge-patch+json")
    return current


def _scale(replicas: int) -> None:
    kube.api("PATCH", kube.ns_path("deployments", MODEL, "apis/apps/v1") + "/scale",
             {"spec": {"replicas": replicas}}, content_type="application/merge-patch+json")


def _jobs() -> list[dict]:
    return kube.api("GET", kube.ns_path("jobs", group="apis/batch/v1"),
                    query={"labelSelector": AI_SELECTOR}).get("items", [])


def _active_jobs() -> list[dict]:
    return [job for job in _jobs() if not kube.terminal(job)]


def _create_worker(reason: str) -> str:
    template = kube.api("GET", kube.ns_path("cronjobs", WORKER_TEMPLATE, "apis/batch/v1"))
    name = f"d00s-ai-{reason}-{uuid.uuid4().hex[:8]}"
    labels = dict(template["spec"]["jobTemplate"].get("metadata", {}).get("labels", {}))
    labels.update({"app.kubernetes.io/name": "d00s-ai-remediator", "factory.d00s.org/reason": reason})
    body = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": kube.NAMESPACE, "labels": labels},
        "spec": template["spec"]["jobTemplate"]["spec"],
    }
    kube.api("POST", kube.ns_path("jobs", group="apis/batch/v1"), body)
    return name


def start(mode: str, hours: int | None, run_scan: bool) -> dict:
    deadline = (_now() + dt.timedelta(hours=hours)).isoformat() if hours else None
    _scale(1)
    current_job = _create_worker(mode) if run_scan and not _active_jobs() else None
    _write_state({"mode": mode, "deadline": deadline, "extensions": 0,
                  "current_job": current_job, "started_at": _now().isoformat()})
    return status()


def stop() -> dict:
    for job in _active_jobs():
        name = job["metadata"]["name"]
        kube.api("DELETE", kube.ns_path("jobs", name, "apis/batch/v1"),
                 {"propagationPolicy": "Background"})
    _scale(0)
    _write_state({"mode": "off", "deadline": None, "extensions": 0, "current_job": None})
    return status()


def status() -> dict:
    state = _state()
    deployment = kube.api("GET", kube.ns_path("deployments", MODEL, "apis/apps/v1"))
    desired = deployment.get("spec", {}).get("replicas", 0)
    ready = deployment.get("status", {}).get("readyReplicas", 0)
    active = _active_jobs()
    return {
        "mode": state.get("mode", "off"),
        "model": "ready" if ready else ("starting" if desired else "stopped"),
        "model_memory": "4 GiB limit · Kubernetes worker",
        "timer": "active",
        "timer_enabled": True,
        "scan": active[0]["metadata"]["name"] if active else "idle",
        "deadline": state.get("deadline"),
        "current_job": state.get("current_job"),
        "last_run": state.get("last_run"),
    }


def command(action: str) -> dict:
    if action not in VALID_ACTIONS:
        raise ValueError("invalid AI control action")
    if action == "status":
        return status()
    if action == "enable":
        return start("monitoring", 2, True)
    if action == "development":
        return start("development", 2, False)
    if action == "stay":
        return start("stay", None, False)
    if action == "scan":
        return start("scan", 2, True)
    return stop()
