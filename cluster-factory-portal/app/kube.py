from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

import yaml

NAMESPACE = os.getenv("POD_NAMESPACE", "factory")
WORKER_IMAGE = os.environ["WORKER_IMAGE"]
SSH_SECRET = os.getenv("SSH_SECRET", "cluster-factory-portal-ssh")
SSH_CONFIG = os.getenv("SSH_CONFIG", "cluster-factory-expiry-ssh")
TTL_RE = re.compile(r"^[1-9][0-9]*[hdw]$")
API = f"https://{os.environ.get('KUBERNETES_SERVICE_HOST', 'kubernetes.default.svc')}:{os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS', '443')}"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


class KubeError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def api(method: str, path: str, payload: Any = None, query: dict | None = None,
        content_type="application/json") -> Any:
    if query:
        path += "?" + urllib.parse.urlencode(query)
    data = json.dumps(payload).encode() if payload is not None else None
    token = open(TOKEN_PATH, encoding="utf-8").read().strip()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=45, context=ssl.create_default_context(cafile=CA_PATH)) as response:
            body = response.read()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        raise KubeError(exc.code, exc.read().decode(errors="replace")) from exc


def ns_path(resource: str, name: str | None = None, group="api/v1") -> str:
    path = f"/{group}/namespaces/{urllib.parse.quote(NAMESPACE)}/{resource}"
    return path + (f"/{urllib.parse.quote(name)}" if name else "")


def labels(selector: str) -> list[dict]:
    return api("GET", ns_path("configmaps"), query={"labelSelector": selector}).get("items", [])


def read_json_configmap(name: str, key: str, fallback: Any) -> Any:
    try:
        return json.loads(api("GET", ns_path("configmaps", name)).get("data", {}).get(key, ""))
    except (KubeError, json.JSONDecodeError):
        return fallback


def policy() -> dict:
    return read_json_configmap("cluster-factory-portal-policy", "policy.json", {
        "default_user_cluster_limit": 1, "user_overrides": {}, "max_ttl_regular": "7d"})


def inventory() -> dict:
    return read_json_configmap("cluster-factory-portal-inventory", "inventory.json", {
        "updated_at": None, "clusters": {}, "proxmox": {"status": "awaiting-observer"}})


def versions() -> dict:
    catalog = yaml.safe_load(api("GET", ns_path("configmaps", "cluster-factory-version-catalog"))["data"]["catalog.yml"])
    candidates = json.loads(api("GET", ns_path("configmaps", "cluster-factory-version-candidates"))["data"]["candidates.json"])
    result = {}
    for name, stable in catalog["components"].items():
        values = [{"value": str(stable["stable"]), "tested": bool(stable.get("tested"))}]
        candidate = candidates.get("components", {}).get(name, {}).get("candidate")
        if candidate and str(candidate) != values[0]["value"]:
            values.append({"value": str(candidate), "tested": False})
        result[name] = values
    return result


def profiles() -> dict:
    return json.loads(api("GET", ns_path("configmaps", "cluster-factory-portal-config"))["data"]["profiles.json"])


def terminal(job: dict) -> bool:
    status = job.get("status", {})
    return bool(status.get("completionTime") or status.get("failed"))


def active_jobs() -> list[dict]:
    jobs = api("GET", ns_path("jobs", group="apis/batch/v1"),
               query={"labelSelector": "app.kubernetes.io/name=cluster-factory-job"}).get("items", [])
    return [job for job in jobs if not terminal(job)]


def cluster_records() -> list[dict]:
    records = []
    for configmap in labels("factory.d00s.org/type=cluster-record"):
        try:
            record = json.loads(configmap["data"]["record.json"])
            record["resource_name"] = configmap["metadata"]["name"]
            records.append(record)
        except (KeyError, json.JSONDecodeError):
            continue
    return records


def quota_for(user: dict) -> int:
    current = policy()
    return int(current.get("user_overrides", {}).get(user["sub"], current.get("default_user_cluster_limit", 1)))


def claim_profile(profile: str, holder: str) -> None:
    body = {"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
            "metadata": {"name": f"factory-profile-{profile}", "namespace": NAMESPACE,
                         "labels": {"app.kubernetes.io/name": "cluster-factory-lock"}},
            "spec": {"holderIdentity": holder, "acquireTime": dt.datetime.now(dt.timezone.utc).isoformat(),
                     "leaseDurationSeconds": 10800}}
    try:
        api("POST", ns_path("leases", group="apis/coordination.k8s.io/v1"), body)
    except KubeError as exc:
        if exc.status == 409:
            raise ValueError(f"Profile {profile} is already claimed by another job") from exc
        raise


def release_profile(profile: str) -> None:
    try:
        api("DELETE", ns_path("leases", f"factory-profile-{profile}", group="apis/coordination.k8s.io/v1"),
            {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Background"})
    except KubeError as exc:
        if exc.status != 404:
            raise


def audit(job_id: str, record: dict) -> None:
    body = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": f"factory-audit-{job_id}", "namespace": NAMESPACE,
                         "labels": {"factory.d00s.org/type": "audit", "factory.d00s.org/action": record["action"]}},
            "data": {"record.json": json.dumps(record, sort_keys=True)}}
    api("POST", ns_path("configmaps"), body)


def patch_audit(job_id: str, changes: dict) -> None:
    name = f"factory-audit-{job_id}"
    configmap = api("GET", ns_path("configmaps", name))
    record = json.loads(configmap["data"]["record.json"]); record.update(changes)
    api("PATCH", ns_path("configmaps", name), {"data": {"record.json": json.dumps(record, sort_keys=True)}},
        content_type="application/merge-patch+json")


def submit(action: str, request_data: dict, user: dict, source_ip: str) -> str:
    profile = request_data["profile"]; job_id = uuid.uuid4().hex[:12]; claim_profile(profile, job_id)
    try:
        spec_name = f"factory-request-{job_id}"; owner = hashlib.sha256(user["sub"].encode()).hexdigest()[:20]
        api("POST", ns_path("configmaps"), {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": spec_name, "namespace": NAMESPACE,
                         "labels": {"factory.d00s.org/type": "request"}},
            "data": {"request.yaml": yaml.safe_dump({"cluster_request": request_data}, sort_keys=False)}})
        job_name = f"factory-{action}-{job_id}"
        audit(job_id, {"schema": 1, "job_id": job_id, "job_name": job_name, "action": action,
                       "profile": profile, "owner_sub": user["sub"], "owner": user.get("preferred_username"),
                       "source_ip": source_ip, "submitted_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                       "status": "submitted", "request": request_data})
        labels_map = {"app.kubernetes.io/name": "cluster-factory-job", "factory.d00s.org/action": action,
                      "factory.d00s.org/profile": profile, "factory.d00s.org/owner": owner,
                      "factory.d00s.org/job-id": job_id}
        container = {"name": "runner", "image": WORKER_IMAGE, "imagePullPolicy": "IfNotPresent",
            "command": ["python3", "-m", "app.job_runner"],
            "env": [{"name": "FACTORY_ACTION", "value": action}, {"name": "FACTORY_JOB_ID", "value": job_id},
                    {"name": "FACTORY_PROFILE", "value": profile},
                    {"name": "FACTORY_RETAIN_DATA", "value": str(request_data.get("retain_data", False)).lower()}],
            "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                          "limits": {"cpu": "500m", "memory": "256Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "request", "mountPath": "/request", "readOnly": True},
                             {"name": "ssh-key", "mountPath": "/ssh", "readOnly": True},
                             {"name": "ssh-config", "mountPath": "/ssh-config", "readOnly": True},
                             {"name": "tmp", "mountPath": "/tmp"}]}
        pod_spec = {"serviceAccountName": "cluster-factory-runner", "automountServiceAccountToken": False,
            "restartPolicy": "Never", "imagePullSecrets": [{"name": "cluster-factory-portal-harbor"}],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [container],
            "volumes": [{"name": "request", "configMap": {"name": spec_name, "defaultMode": 256}},
                        {"name": "ssh-key", "secret": {"secretName": SSH_SECRET, "defaultMode": 256}},
                        {"name": "ssh-config", "configMap": {"name": SSH_CONFIG, "defaultMode": 292}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}]}
        job = {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": job_name, "namespace": NAMESPACE, "labels": labels_map,
                         "annotations": {"factory.d00s.org/owner-name": user.get("preferred_username", "unknown")}},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 10800, "ttlSecondsAfterFinished": 604800,
                     "template": {"metadata": {"labels": labels_map}, "spec": pod_spec}}}
        api("POST", ns_path("jobs", group="apis/batch/v1"), job)
        return job_id
    except Exception:
        release_profile(profile); raise


def job_for(job_id: str) -> dict:
    items = api("GET", ns_path("jobs", group="apis/batch/v1"),
                query={"labelSelector": f"factory.d00s.org/job-id={job_id}"}).get("items", [])
    if not items:
        raise KeyError(job_id)
    return items[0]


def pods_for_job(name: str) -> list[dict]:
    return api("GET", ns_path("pods"), query={"labelSelector": f"job-name={name}"}).get("items", [])


def pod_log(name: str) -> str:
    path = ns_path("pods", name) + "/log?" + urllib.parse.urlencode({"timestamps": "true"})
    token = open(TOKEN_PATH, encoding="utf-8").read().strip()
    req = urllib.request.Request(API + path, headers={"Authorization": f"Bearer {token}", "Accept": "text/plain"})
    with urllib.request.urlopen(req, timeout=45, context=ssl.create_default_context(cafile=CA_PATH)) as response:
        return response.read().decode(errors="replace")


def reconcile() -> None:
    jobs = api("GET", ns_path("jobs", group="apis/batch/v1"),
               query={"labelSelector": "app.kubernetes.io/name=cluster-factory-job"}).get("items", [])
    for job in jobs:
        if not terminal(job): continue
        labels_map = job["metadata"]["labels"]
        job_id = labels_map["factory.d00s.org/job-id"]; profile = labels_map["factory.d00s.org/profile"]
        action = labels_map["factory.d00s.org/action"]; succeeded = bool(job.get("status", {}).get("succeeded"))
        try:
            existing = json.loads(api("GET", ns_path("configmaps", f"factory-audit-{job_id}"))["data"]["record.json"])
            if existing.get("reconciled"): continue
            patch_audit(job_id, {"status": "succeeded" if succeeded else "failed",
                                 "completed_at": dt.datetime.now(dt.timezone.utc).isoformat()})
        except KubeError:
            release_profile(profile); continue
        if succeeded:
            record = json.loads(api("GET", ns_path("configmaps", f"factory-audit-{job_id}"))["data"]["record.json"])
            cluster_name = f"factory-cluster-{profile}"
            if action == "create":
                ttl = record["request"]["lifecycle"]["ttl"]; amount, unit = int(ttl[:-1]), ttl[-1]
                delta = {"h": dt.timedelta(hours=amount), "d": dt.timedelta(days=amount),
                         "w": dt.timedelta(weeks=amount)}[unit]
                cluster = {"profile": profile, "owner_sub": record["owner_sub"], "owner": record["owner"],
                    "created_at": record["completed_at"],
                    "expires_at": (dt.datetime.now(dt.timezone.utc) + delta).isoformat(),
                    "url": profiles()[profile]["url"], "request": record["request"], "managed_by_portal": True}
                body = {"apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"name": cluster_name, "namespace": NAMESPACE,
                                     "labels": {"factory.d00s.org/type": "cluster-record"}},
                        "data": {"record.json": json.dumps(cluster, sort_keys=True)}}
                try: api("POST", ns_path("configmaps"), body)
                except KubeError as exc:
                    if exc.status == 409:
                        api("PATCH", ns_path("configmaps", cluster_name), {"data": body["data"]},
                            content_type="application/merge-patch+json")
                    else: raise
            else:
                try: api("DELETE", ns_path("configmaps", cluster_name), {"apiVersion": "v1", "kind": "DeleteOptions"})
                except KubeError as exc:
                    if exc.status != 404: raise
        release_profile(profile); patch_audit(job_id, {"reconciled": True})


def update_policy(payload: dict) -> None:
    api("PATCH", ns_path("configmaps", "cluster-factory-portal-policy"),
        {"data": {"policy.json": json.dumps(payload, sort_keys=True)}}, content_type="application/merge-patch+json")
