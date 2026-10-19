"""Refresh sanitized portal inventory through the restricted Atlantis endpoint."""

import json
import os
import subprocess
import sys

from kubernetes import client, config


def main() -> int:
    ssh = ["ssh", "-p", "2200", "-i", "/ssh/id_ed25519", "-o", "BatchMode=yes",
           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=/ssh-config/known_hosts", "-o", "ConnectTimeout=15",
           "edward@192.168.31.254", "observe"]
    result = subprocess.run(ssh, text=True, capture_output=True, timeout=180, check=False)
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        return result.returncode
    payload = json.loads(result.stdout)
    config.load_incluster_config()
    api = client.CoreV1Api()
    namespace = os.getenv("POD_NAMESPACE", "factory")
    api.patch_namespaced_config_map("cluster-factory-portal-inventory", namespace,
                                    {"data": {"inventory.json": json.dumps(payload, sort_keys=True)}})
    print(json.dumps({"updated_at": payload["updated_at"], "clusters": list(payload["clusters"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
