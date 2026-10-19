"""Short-lived worker: copy a sanitized request to Atlantis and run playbooks there."""

import os
import pathlib
import subprocess
import sys


def stage(name: str) -> None:
    print(f"FACTORY_STAGE {name}", flush=True)


def main() -> int:
    action = os.environ["FACTORY_ACTION"]
    job_id = os.environ["FACTORY_JOB_ID"]
    profile = os.environ["FACTORY_PROFILE"]
    retain = os.getenv("FACTORY_RETAIN_DATA", "false") == "true"
    request = pathlib.Path("/request/request.yaml").read_bytes()
    remote_spec = f"/home/edward/.local/share/cluster-factory/portal/requests/{job_id}.yaml"
    ssh = ["ssh", "-p", "2200", "-i", "/ssh/id_ed25519", "-o", "BatchMode=yes",
           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=/ssh-config/known_hosts", "-o", "ConnectTimeout=15",
           "edward@192.168.31.254"]
    stage("request-transfer")
    install = subprocess.run(ssh + [f"umask 077; mkdir -p $(dirname {remote_spec}); cat > {remote_spec}"],
                             input=request, check=False)
    if install.returncode:
        return install.returncode
    if action == "create":
        stage("preflight-and-create")
        remote = (
            "cd /home/edward/k8s/ansible && "
            f"python3 cluster-factory/scripts/build_controller.py --ansible-dir /home/edward/k8s/ansible "
            f"--cluster-spec {remote_spec} --confirm {profile} --mode replace"
        )
    elif action == "delete":
        stage("guarded-delete")
        flags = "-e retain_cluster_data=true" if retain else f"-e confirm_data_destroy={profile}"
        remote = (
            "cd /home/edward/k8s/ansible && "
            "ansible-playbook cluster-factory/playbooks/delete.yml "
            f"-e cluster_spec={remote_spec} -e execute_delete=true -e confirm_destroy={profile} {flags}"
        )
    else:
        raise ValueError("unsupported action")
    result = subprocess.run(ssh + [remote], check=False)
    stage("complete" if result.returncode == 0 else "failed")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
