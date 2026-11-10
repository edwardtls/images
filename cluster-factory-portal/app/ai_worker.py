"""Bounded cluster scan with narrowly-scoped deterministic backup remediation.

Backups are the CloudNativePG Barman Cloud backups of every database cluster.
"""

from __future__ import annotations

import datetime as dt
from email.message import EmailMessage
import json
import os
import smtplib
import socket
import time
import urllib.error
import urllib.request
import uuid

from . import ai_control, kube

CNPG = "/apis/postgresql.cnpg.io/v1"
BACKUP_PLUGIN = "barman-cloud.cloudnative-pg.io"
BACKUP_MAX_AGE = dt.timedelta(hours=30)  # daily base backups, plus slack
BACKUP_ACTIVE = {"pending", "started", "running", "finalizing"}
MODEL_URL = os.getenv("AI_MODEL_URL", "http://d00s-ai-model.factory.svc.cluster.local:11434/api/chat")
MODEL_TAGS_URL = MODEL_URL.rsplit("/", 1)[0] + "/tags"
ALERTS_PATH = ("/api/v1/namespaces/monitoring/services/"
               "http:d00s-kube-prometheus-stack-alertmanager:9093/proxy/api/v2/alerts")


def _items(path: str, query: dict | None = None) -> list[dict]:
    return kube.api("GET", path, query=query).get("items", [])


def _ts(value: str | None) -> dt.datetime:
    if not value:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _phase(backup: dict) -> str:
    return backup.get("status", {}).get("phase", "pending")


def _retry(namespace: str, cluster: str) -> str:
    name = f"ai-retry-{cluster[:35]}-{uuid.uuid4().hex[:8]}"
    body = {"apiVersion": "postgresql.cnpg.io/v1", "kind": "Backup",
            "metadata": {"name": name, "namespace": namespace,
                         "labels": {"app.kubernetes.io/managed-by": "d00s-ai-remediator"}},
            "spec": {"cluster": {"name": cluster}, "method": "plugin", "target": "prefer-standby",
                     "pluginConfiguration": {"name": BACKUP_PLUGIN}}}
    kube.api("POST", f"{CNPG}/namespaces/{namespace}/backups", body)
    return name


def _backup_actions(now: dt.datetime | None = None) -> tuple[list[str], list[dict]]:
    """Check the Barman Cloud backups of every CNPG cluster.

    The only repairs are starting a new base backup when the latest one failed and none
    is running, and deleting failed Backups once a newer one has succeeded.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    findings: list[str] = []
    actions: list[dict] = []
    by_cluster: dict[tuple[str, str], list[dict]] = {}
    for backup in _items(f"{CNPG}/backups"):
        key = (backup["metadata"]["namespace"], backup.get("spec", {}).get("cluster", {}).get("name", ""))
        by_cluster.setdefault(key, []).append(backup)
    for cluster in _items(f"{CNPG}/clusters"):
        namespace, name = cluster["metadata"]["namespace"], cluster["metadata"]["name"]
        status = cluster.get("status", {})
        archiving = next((c for c in status.get("conditions", []) if c.get("type") == "ContinuousArchiving"), None)
        if archiving and archiving.get("status") != "True":
            findings.append(f"WAL archiving failing for {namespace}/{name}: {archiving.get('message', '')[:160]}")
        backups = sorted(by_cluster.get((namespace, name), []),
                         key=lambda item: _ts(item["metadata"].get("creationTimestamp")), reverse=True)
        if not backups:
            continue
        done = [b for b in backups if _phase(b) == "completed"]
        newest_success = max((_ts(b["status"].get("stoppedAt")) for b in done), default=None)
        if newest_success is None or now - newest_success > BACKUP_MAX_AGE:
            findings.append(f"No successful base backup for {namespace}/{name} in the last 30 hours")
        latest = backups[0]
        if _phase(latest) == "failed":
            findings.append(f"Latest base backup for {namespace}/{name} failed: {latest['metadata']['name']}")
            if not any(_phase(b) in BACKUP_ACTIVE for b in backups):
                actions.append({"runbook": "retry-failed-backup", "target": f"{namespace}/{name}",
                                "detail": _retry(namespace, name), "status": "started"})
        if newest_success is not None:
            for backup in backups:
                if _phase(backup) == "failed" and _ts(backup["metadata"].get("creationTimestamp")) < newest_success:
                    backup_name = backup["metadata"]["name"]
                    kube.api("DELETE", f"{CNPG}/namespaces/{namespace}/backups/{backup_name}")
                    actions.append({"runbook": "cleanup-superseded-failure", "target": f"{namespace}/{name}",
                                    "detail": backup_name, "status": "completed"})
    return findings, actions


def _health() -> tuple[list[str], dict]:
    nodes = _items("/api/v1/nodes")
    pods = _items("/api/v1/pods")
    findings: list[str] = []
    bad_nodes = []
    for node in nodes:
        ready = next((condition for condition in node.get("status", {}).get("conditions", [])
                      if condition.get("type") == "Ready"), {})
        if ready.get("status") != "True":
            bad_nodes.append(node["metadata"]["name"])
    if bad_nodes:
        findings.append("Nodes not ready: " + ", ".join(bad_nodes))
    bad_pods = []
    for pod in pods:
        namespace = pod["metadata"]["namespace"]
        if namespace == "factory" and pod["metadata"]["name"].startswith("d00s-ai-"):
            continue
        reasons = [status.get("state", {}).get("waiting", {}).get("reason")
                   for status in pod.get("status", {}).get("containerStatuses", [])]
        reasons = [reason for reason in reasons if reason in
                   {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError"}]
        if reasons:
            bad_pods.append(f"{namespace}/{pod['metadata']['name']}:{reasons[0]}")
    if bad_pods:
        findings.append("Unhealthy pods: " + ", ".join(bad_pods[:25]))
    alerts = []
    try:
        for alert in kube.api("GET", ALERTS_PATH):
            labels = alert.get("labels", {})
            status = alert.get("status", {})
            name = labels.get("alertname", "unknown")
            if status.get("state") == "active" and name != "Watchdog":
                alerts.append({"name": name, "severity": labels.get("severity", "unknown"),
                               "namespace": labels.get("namespace"),
                               "summary": alert.get("annotations", {}).get("summary", "")[:240]})
        if alerts:
            findings.append("Firing alerts: " + ", ".join(
                f"{item['name']}[{item['severity']}]" for item in alerts[:25]))
    except kube.KubeError as exc:
        findings.append(f"Alertmanager query failed with Kubernetes API status {exc.status}")
    return findings, {"nodes": len(nodes), "pods": len(pods), "bad_nodes": bad_nodes,
                      "bad_pods": bad_pods[:25], "alerts": alerts[:25]}


def _advisory(summary: dict) -> dict:
    body = json.dumps({
        "model": "qwen3.5:2b", "stream": False, "think": False,
        "messages": [{"role": "system", "content":
                      "You are a Kubernetes incident advisor. Return compact JSON with severity, summary and findings. Never propose destructive actions."},
                     {"role": "user", "content": json.dumps(summary, separators=(",", ":"))}],
        "options": {"num_predict": 180, "num_ctx": 2048, "temperature": 0.1},
    }).encode()
    request = urllib.request.Request(MODEL_URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=150) as response:
        result = json.loads(response.read())
    content = result.get("message", {}).get("content", "")
    try:
        start, end = content.index("{"), content.rindex("}") + 1
        return json.loads(content[start:end])
    except (ValueError, json.JSONDecodeError):
        return {"severity": "info", "summary": content[:500] or "No advisory returned", "findings": []}


def _wait_for_model() -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(MODEL_TAGS_URL, timeout=5) as response:
                if response.status == 200:
                    return
        except (OSError, TimeoutError, urllib.error.URLError, socket.timeout):
            time.sleep(3)
    raise TimeoutError("model did not become ready within 180 seconds")


def _email(subject: str, text: str) -> None:
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    recipient = os.getenv("CONTACT_RECIPIENT") or username
    if not all((username, password, recipient)):
        return
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = username
    message["To"] = recipient
    message.set_content(text)
    with smtplib.SMTP(os.getenv("SMTP_HOST", "smtp.gmail.com"), int(os.getenv("SMTP_PORT", "587")), timeout=30) as smtp:
        smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(message)


def main() -> None:
    started = dt.datetime.now(dt.timezone.utc)
    findings: list[str] = []
    actions: list[dict] = []
    error = None
    advisory = None
    try:
        health_findings, health = _health()
        findings.extend(health_findings)
        backup_findings, backup_actions = _backup_actions()
        findings.extend(backup_findings)
        actions.extend(backup_actions)
        # The model is advisory; a slow or unavailable model must never hide deterministic repairs.
        try:
            _wait_for_model()
            advisory = _advisory({"findings": findings, "actions": actions, "health": health})
        except Exception as exc:  # advisory failure is reported, not fatal
            findings.append(f"Advisory model unavailable: {type(exc).__name__}")
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finished = dt.datetime.now(dt.timezone.utc)
    last_run = {
        "state": "failed" if error else "completed", "started_at": started.isoformat(),
        "finished_at": finished.isoformat(), "duration_seconds": int((finished - started).total_seconds()),
        "analysis": advisory or {"severity": "warning" if findings else "info",
                                  "summary": "Cluster scan completed", "findings": findings},
        "actions": actions, "error": error,
    }
    lines = [f"State: {last_run['state']}", "", "Findings:"] + ([f"- {item}" for item in findings] or ["- none"])
    lines += ["", "Validated actions:"] + ([f"- {a['runbook']}: {a['target']} ({a['detail']})" for a in actions] or ["- none"])
    if error:
        lines += ["", "Error:", error]
    try:
        _email(f"D00S AI cluster scan: {last_run['state']}", "\n".join(lines))
        last_run["email"] = "sent"
    except Exception as exc:
        last_run["email"] = f"failed: {type(exc).__name__}"
        findings.append(f"Email delivery failed: {type(exc).__name__}")
    state = ai_control._write_state({"last_run": last_run, "current_job": None})
    if state.get("mode") == "scan":
        ai_control._scale(0)
        ai_control._write_state({"mode": "off", "deadline": None, "current_job": None})
    if error:
        raise RuntimeError(error)


if __name__ == "__main__":
    main()
