# Cluster Factory Portal image

FastAPI portal for the d00s disposable-cluster factory. Keycloak provides OIDC
identity and group claims. Kubernetes Leases serialize each profile, Jobs own
long-running operations, ConfigMaps retain audit/cluster records, and Atlantis
continues to execute the existing Ansible playbooks.

Runtime roles:

- default command: authenticated web UI and API;
- `python -m app.job_runner`: short-lived create/delete trigger;
- `python -m app.observer`: periodic sanitized inventory refresh.

The image contains no credentials. Vault Secrets Operator supplies the OIDC,
SMTP, Harbor pull, and restricted SSH material at deployment time.
