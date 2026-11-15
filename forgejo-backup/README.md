# Forgejo coordinated backup image

This non-root image quiesces Forgejo, requests a CloudNativePG backup of the
shared platform cluster, archives the Forgejo data PVC, resumes Forgejo, and
uploads the archive plus a correlation manifest to the internal S3 service.
The manifest records the CNPG backup name and the PITR target time that matches
the repository archive. Uploads are read back and SHA-256 verified.

`restore-check.sh` downloads one backup into an isolated volume, verifies its
checksum, extracts it and runs `git fsck --full` against every bare repository.
The Kubernetes manifests, schedule, RBAC and restore runbook live in the d00s
GitOps repository under `d00s/forgejo/`.

The image deliberately does not ship `kubectl`. `kube.py` uses Python's standard
library to call only the Kubernetes endpoints allowed by the backup service
account, avoiding an otherwise unnecessary Go client and its dependency CVEs.
