#!/usr/bin/env python3
"""Minimal Kubernetes API client for the backup job's narrow RBAC surface."""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
base = f"https://{host}:{port}"
sa = "/var/run/secrets/kubernetes.io/serviceaccount"
token = open(f"{sa}/token", encoding="utf-8").read().strip()
context = ssl.create_default_context(cafile=f"{sa}/ca.crt")


def request(method, path, body=None, content_type="application/json"):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise SystemExit(f"Kubernetes API {method} {path}: {exc.code}: {detail}") from exc


command, *args = sys.argv[1:]
if command == "replicas":
    namespace, deployment = args
    obj = request("GET", f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment}")
    print(obj["spec"].get("replicas", 1))
elif command == "scale":
    namespace, deployment, replicas = args
    request(
        "PATCH",
        f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment}/scale",
        {"spec": {"replicas": int(replicas)}},
        "application/merge-patch+json",
    )
elif command == "wait-no-pods":
    namespace, selector, timeout = args
    deadline = time.monotonic() + int(timeout)
    query = urllib.parse.urlencode({"labelSelector": selector})
    while time.monotonic() < deadline:
        if not request("GET", f"/api/v1/namespaces/{namespace}/pods?{query}")["items"]:
            break
        time.sleep(2)
    else:
        raise SystemExit("timed out waiting for Forgejo pods to stop")
elif command == "wait-ready":
    namespace, deployment, replicas, timeout = args
    wanted = int(replicas)
    deadline = time.monotonic() + int(timeout)
    path = f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment}"
    while time.monotonic() < deadline:
        obj = request("GET", path)
        if obj.get("status", {}).get("availableReplicas", 0) >= wanted:
            break
        time.sleep(2)
    else:
        raise SystemExit("timed out waiting for Forgejo deployment readiness")
elif command == "create-backup":
    namespace, name, cluster, backup_id = args
    request(
        "POST",
        f"/apis/postgresql.cnpg.io/v1/namespaces/{namespace}/backups",
        {
            "apiVersion": "postgresql.cnpg.io/v1",
            "kind": "Backup",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "backup.d00s.org/application": "forgejo",
                    "backup.d00s.org/backup-id": backup_id,
                },
            },
            "spec": {
                "cluster": {"name": cluster},
                "method": "plugin",
                "target": "prefer-standby",
                "pluginConfiguration": {"name": "barman-cloud.cloudnative-pg.io"},
            },
        },
    )
elif command == "backup-field":
    namespace, name, field = args
    obj = request("GET", f"/apis/postgresql.cnpg.io/v1/namespaces/{namespace}/backups/{name}")
    print(obj.get("status", {}).get(field, ""))
else:
    raise SystemExit("unknown command")
