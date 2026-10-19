"""Short-lived worker: copy a sanitized request to Atlantis and run playbooks there."""

import os
import subprocess
import sys


def stage(name: str) -> None:
    print(f"FACTORY_STAGE {name}", flush=True)


def private_key() -> str:
    destination = "/tmp/id_ed25519"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as target, open("/ssh/id_ed25519", "rb") as source:
        target.write(source.read())
    os.chmod(destination, 0o600)
    return destination


def main() -> int:
    action = os.environ["FACTORY_ACTION"]
    job_id = os.environ["FACTORY_JOB_ID"]
    profile = os.environ["FACTORY_PROFILE"]
    retain = os.getenv("FACTORY_RETAIN_DATA", "false") == "true"
    request = open("/request/request.yaml", "rb").read()
    ssh = ["ssh", "-p", "2200", "-i", private_key(), "-o", "BatchMode=yes",
           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=/ssh-config/known_hosts", "-o", "ConnectTimeout=15",
           "edward@192.168.31.254"]
    if action not in {"create", "delete"}:
        raise ValueError("unsupported action")
    stage("preflight-and-create" if action == "create" else "guarded-delete")
    result = subprocess.run(ssh + [f"run {job_id} {action} {profile} {str(retain).lower()}"],
                            input=request, check=False)
    stage("complete" if result.returncode == 0 else "failed")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
