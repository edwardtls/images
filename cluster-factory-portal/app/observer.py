"""Refresh sanitized portal inventory through the restricted Atlantis endpoint."""

import json
import os
import ssl
import subprocess
import sys
import urllib.request


def private_key() -> str:
    destination = "/tmp/id_ed25519"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as target, open("/ssh/id_ed25519", "rb") as source:
        target.write(source.read())
    os.chmod(destination, 0o600)
    return destination


def patch_inventory(payload: dict) -> None:
    namespace = os.getenv("POD_NAMESPACE", "factory")
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    path = f"/api/v1/namespaces/{namespace}/configmaps/cluster-factory-portal-inventory"
    token = open("/var/run/secrets/kubernetes.io/serviceaccount/token", encoding="utf-8").read().strip()
    body = json.dumps({"data": {"inventory.json": json.dumps(payload, sort_keys=True)}}).encode()
    req = urllib.request.Request(f"https://{host}:{port}{path}", data=body, method="PATCH", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/merge-patch+json"})
    context = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    with urllib.request.urlopen(req, timeout=45, context=context):
        pass


def main() -> int:
    ssh = ["ssh", "-p", "2200", "-i", private_key(), "-o", "BatchMode=yes",
           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=/ssh-config/known_hosts", "-o", "ConnectTimeout=15",
           "edward@192.168.31.254", "observe"]
    result = subprocess.run(ssh, text=True, capture_output=True, timeout=180, check=False)
    if result.returncode:
        print(result.stderr, file=sys.stderr); return result.returncode
    payload = json.loads(result.stdout); patch_inventory(payload)
    print(json.dumps({"updated_at": payload["updated_at"], "clusters": list(payload["clusters"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
