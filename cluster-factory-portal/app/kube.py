from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import uuid
from typing import Any

import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException

NAMESPACE = os.getenv("POD_NAMESPACE", "factory")
WORKER_IMAGE = os.environ["WORKER_IMAGE"]
SSH_SECRET = os.getenv("SSH_SECRET", "cluster-factory-expiry-ssh")
SSH_CONFIG = os.getenv("SSH_CONFIG", "cluster-factory-expiry-ssh")
TTL_RE = re.compile(r"^[1-9][0-9]*[hdw]$")

config.load_incluster_config()
core = client.CoreV1Api()
batch = client.BatchV1Api()
coordination = client.CoordinationV1Api()


def labels(selector: str) -> list[client.V1ConfigMap]:
    return core.list_namespaced_config_map(NAMESPACE, label_selector=selector).items


def read_json_configmap(name: str, key: str, fallback: Any) -> Any:
    try:
        cm = core.read_namespaced_config_map(name, NAMESPACE)
        return json.loads((cm.data or {}).get(key, ""))
    except (ApiException, json.JSONDecodeError):
        return fallback


def policy() -> dict:
    return read_json_configmap("cluster-factory-portal-policy", "policy.json", {
        "default_user_cluster_limit": 1, "user_overrides": {}, "max_ttl_regular": "7d"
    })


def inventory() -> dict:
    return read_json_configmap("cluster-factory-portal-inventory", "inventory.json", {
        "updated_at": None, "clusters": {}, "proxmox": {"status": "awaiting-observer"}
    })


def versions() -> dict:
    catalog_cm = core.read_namespaced_config_map("cluster-factory-version-catalog", NAMESPACE)
    candidates_cm = core.read_namespaced_config_map("cluster-factory-version-candidates", NAMESPACE)
    catalog = yaml.safe_load(catalog_cm.data["catalog.yml"])
    candidates = json.loads(candidates_cm.data["candidates.json"])
    result = {}
    for name, stable in catalog["components"].items():
        values = [{"value": str(stable["stable"]), "tested": bool(stable.get("tested"))}]
        candidate = candidates.get("components", {}).get(name, {}).get("candidate")
        if candidate and str(candidate) != values[0]["value"]:
            values.append({"value": str(candidate), "tested": False})
        result[name] = values
    return result


def profiles() -> dict:
    cm = core.read_namespaced_config_map("cluster-factory-portal-config", NAMESPACE)
    return json.loads(cm.data["profiles.json"])


def active_jobs() -> list[client.V1Job]:
    jobs = batch.list_namespaced_job(NAMESPACE, label_selector="app.kubernetes.io/name=cluster-factory-job").items
    return [job for job in jobs if not job.status.completion_time and not (job.status.failed or 0)]


def cluster_records() -> list[dict]:
    records = []
    for cm in labels("factory.d00s.org/type=cluster-record"):
        try:
            record = json.loads(cm.data["record.json"])
            record["resource_name"] = cm.metadata.name
            records.append(record)
        except (KeyError, json.JSONDecodeError):
            continue
    return records


def quota_for(user: dict) -> int:
    current = policy()
    return int(current.get("user_overrides", {}).get(user["sub"], current.get("default_user_cluster_limit", 1)))


def claim_profile(profile: str, holder: str) -> None:
    lease = client.V1Lease(
        metadata=client.V1ObjectMeta(name=f"factory-profile-{profile}", namespace=NAMESPACE,
                                     labels={"app.kubernetes.io/name": "cluster-factory-lock"}),
        spec=client.V1LeaseSpec(holder_identity=holder,
                                acquire_time=dt.datetime.now(dt.timezone.utc), lease_duration_seconds=86400),
    )
    try:
        coordination.create_namespaced_lease(NAMESPACE, lease)
    except ApiException as exc:
        if exc.status == 409:
            raise ValueError(f"Profile {profile} is already claimed by another job") from exc
        raise


def release_profile(profile: str) -> None:
    try:
        coordination.delete_namespaced_lease(f"factory-profile-{profile}", NAMESPACE)
    except ApiException as exc:
        if exc.status != 404:
            raise


def audit(job_id: str, record: dict) -> None:
    body = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(
            name=f"factory-audit-{job_id}", namespace=NAMESPACE,
            labels={"factory.d00s.org/type": "audit", "factory.d00s.org/action": record["action"]},
        ), data={"record.json": json.dumps(record, sort_keys=True)})
    core.create_namespaced_config_map(NAMESPACE, body)


def patch_audit(job_id: str, changes: dict) -> None:
    name = f"factory-audit-{job_id}"
    cm = core.read_namespaced_config_map(name, NAMESPACE)
    record = json.loads(cm.data["record.json"])
    record.update(changes)
    core.patch_namespaced_config_map(name, NAMESPACE, {"data": {"record.json": json.dumps(record, sort_keys=True)}})


def submit(action: str, request_data: dict, user: dict, source_ip: str) -> str:
    profile = request_data["profile"]
    job_id = uuid.uuid4().hex[:12]
    claim_profile(profile, job_id)
    try:
        spec_name = f"factory-request-{job_id}"
        cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name=spec_name, namespace=NAMESPACE,
                                         labels={"factory.d00s.org/type": "request"}),
            data={"request.yaml": yaml.safe_dump({"cluster_request": request_data}, sort_keys=False)})
        core.create_namespaced_config_map(NAMESPACE, cm)
        owner = hashlib.sha256(user["sub"].encode()).hexdigest()[:20]
        job_name = f"factory-{action}-{job_id}"
        env = [client.V1EnvVar(name="FACTORY_ACTION", value=action),
               client.V1EnvVar(name="FACTORY_JOB_ID", value=job_id),
               client.V1EnvVar(name="FACTORY_PROFILE", value=profile),
               client.V1EnvVar(name="FACTORY_RETAIN_DATA", value=str(request_data.get("retain_data", False)).lower())]
        container = client.V1Container(
            name="runner", image=WORKER_IMAGE, image_pull_policy="IfNotPresent",
            command=["python3", "-m", "app.job_runner"], env=env,
            resources=client.V1ResourceRequirements(
                requests={"cpu": "20m", "memory": "32Mi"}, limits={"cpu": "500m", "memory": "256Mi"}),
            security_context=client.V1SecurityContext(allow_privilege_escalation=False,
                                                       read_only_root_filesystem=True,
                                                       capabilities=client.V1Capabilities(drop=["ALL"])),
            volume_mounts=[
                client.V1VolumeMount(name="request", mount_path="/request", read_only=True),
                client.V1VolumeMount(name="ssh-key", mount_path="/ssh", read_only=True),
                client.V1VolumeMount(name="ssh-config", mount_path="/ssh-config", read_only=True),
                client.V1VolumeMount(name="tmp", mount_path="/tmp")])
        pod = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(labels={"app.kubernetes.io/name": "cluster-factory-job",
                                                 "factory.d00s.org/job-id": job_id}),
            spec=client.V1PodSpec(service_account_name="cluster-factory-runner", automount_service_account_token=False,
                restart_policy="Never", security_context=client.V1PodSecurityContext(
                    run_as_non_root=True, run_as_user=65532, run_as_group=65532, fs_group=65532,
                    seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault")),
                containers=[container], volumes=[
                    client.V1Volume(name="request", config_map=client.V1ConfigMapVolumeSource(name=spec_name, default_mode=0o400)),
                    client.V1Volume(name="ssh-key", secret=client.V1SecretVolumeSource(secret_name=SSH_SECRET, default_mode=0o400)),
                    client.V1Volume(name="ssh-config", config_map=client.V1ConfigMapVolumeSource(name=SSH_CONFIG, default_mode=0o444)),
                    client.V1Volume(name="tmp", empty_dir=client.V1EmptyDirVolumeSource(size_limit="64Mi"))]))
        job = client.V1Job(
            metadata=client.V1ObjectMeta(name=job_name, namespace=NAMESPACE,
                labels={"app.kubernetes.io/name": "cluster-factory-job", "factory.d00s.org/action": action,
                        "factory.d00s.org/profile": profile, "factory.d00s.org/owner": owner,
                        "factory.d00s.org/job-id": job_id},
                annotations={"factory.d00s.org/owner-name": user.get("preferred_username", "unknown")}),
            spec=client.V1JobSpec(backoff_limit=0, active_deadline_seconds=10800,
                                  ttl_seconds_after_finished=604800, template=pod))
        audit(job_id, {"schema": 1, "job_id": job_id, "job_name": job_name, "action": action,
                       "profile": profile, "owner_sub": user["sub"],
                       "owner": user.get("preferred_username"), "source_ip": source_ip,
                       "submitted_at": dt.datetime.now(dt.timezone.utc).isoformat(), "status": "submitted",
                       "request": request_data})
        batch.create_namespaced_job(NAMESPACE, job)
        return job_id
    except Exception:
        release_profile(profile)
        raise


def job_for(job_id: str) -> client.V1Job:
    items = batch.list_namespaced_job(NAMESPACE, label_selector=f"factory.d00s.org/job-id={job_id}").items
    if not items:
        raise KeyError(job_id)
    return items[0]


def reconcile() -> None:
    for job in batch.list_namespaced_job(NAMESPACE, label_selector="app.kubernetes.io/name=cluster-factory-job").items:
        if not (job.status.completion_time or (job.status.failed or 0)):
            continue
        job_id = job.metadata.labels["factory.d00s.org/job-id"]
        profile = job.metadata.labels["factory.d00s.org/profile"]
        action = job.metadata.labels["factory.d00s.org/action"]
        succeeded = bool(job.status.succeeded)
        try:
            audit_cm = core.read_namespaced_config_map(f"factory-audit-{job_id}", NAMESPACE)
            existing_audit = json.loads(audit_cm.data["record.json"])
            if existing_audit.get("reconciled"):
                continue
            patch_audit(job_id, {"status": "succeeded" if succeeded else "failed",
                                 "completed_at": dt.datetime.now(dt.timezone.utc).isoformat()})
        except ApiException:
            pass
        if succeeded:
            audit_cm = core.read_namespaced_config_map(f"factory-audit-{job_id}", NAMESPACE)
            record = json.loads(audit_cm.data["record.json"])
            cluster_cm = f"factory-cluster-{profile}"
            if action == "create":
                ttl = record["request"]["lifecycle"]["ttl"]
                amount, unit = int(ttl[:-1]), ttl[-1]
                delta = {"h": dt.timedelta(hours=amount), "d": dt.timedelta(days=amount),
                         "w": dt.timedelta(weeks=amount)}[unit]
                cluster = {"profile": profile, "owner_sub": record["owner_sub"], "owner": record["owner"],
                           "created_at": record["completed_at"],
                           "expires_at": (dt.datetime.now(dt.timezone.utc) + delta).isoformat(),
                           "url": profiles()[profile]["url"], "request": record["request"]}
                body = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=cluster_cm, namespace=NAMESPACE,
                    labels={"factory.d00s.org/type": "cluster-record"}),
                    data={"record.json": json.dumps(cluster, sort_keys=True)})
                try:
                    core.create_namespaced_config_map(NAMESPACE, body)
                except ApiException as exc:
                    if exc.status == 409:
                        core.replace_namespaced_config_map(cluster_cm, NAMESPACE, body)
                    else:
                        raise
            else:
                try:
                    core.delete_namespaced_config_map(cluster_cm, NAMESPACE)
                except ApiException as exc:
                    if exc.status != 404:
                        raise
        release_profile(profile)
        try:
            patch_audit(job_id, {"reconciled": True})
        except ApiException:
            pass


def update_policy(payload: dict) -> None:
    core.patch_namespaced_config_map("cluster-factory-portal-policy", NAMESPACE,
                                     {"data": {"policy.json": json.dumps(payload, sort_keys=True)}})
