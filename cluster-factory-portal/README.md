# Cluster Factory Portal image

Flask portal for the d00s disposable-cluster factory. Keycloak provides OIDC
identity and verified-email self-registration. Kubernetes ConfigMaps retain
pending approvals, independent cluster/security capabilities, audit data and
cluster records. Leases serialize each profile, Jobs own long-running
operations, and Atlantis continues to execute the existing Ansible playbooks.

Runtime roles:

- default command: authenticated web UI and API;
- `python -m app.job_runner`: short-lived create/delete trigger;
- `python -m app.observer`: periodic sanitized inventory refresh.

The image contains no credentials. Vault Secrets Operator supplies the OIDC,
SMTP, Harbor pull, and restricted SSH material at deployment time.

New Keycloak accounts have no Factory access. Their first OIDC return creates a
pending access record and ends the session. The Admin page can approve the
record and independently grant owned-cluster operations or security-dashboard
visibility. The access record is re-read on every authenticated request, so
revocation is immediate. The portal receives no Keycloak administrative
credential; `factory-admins` remains a direct Keycloak operation. Cluster
records, jobs, logs and deletion actions remain restricted to their original
Keycloak subject unless the viewer is an administrator.

The Kubernetes API integration uses the standard library with the mounted
service-account CA and token. Keeping the runtime dependency set small makes
the recurring image audit easier to review.

The administrator-only documentation view reads a GitOps-generated ConfigMap.
Canonical Markdown lives under `d00s/factory-docs`; the portal receives no Git
or GitHub credential. Catalog entries and filenames are strictly validated and
Mistune renders with raw HTML escaped and harmful URL schemes blocked. This
keeps operational documentation reviewable in Git without turning the portal
into a second documentation editor.

The Docs landing page includes a lightweight clickable SVG architecture map.
The map links public edges, routing, Kubernetes, identity, Proxmox/Ceph,
storage and source systems to their canonical runbooks. The Admin page also
correlates retained create/delete audits into cluster lifecycles, showing the
owner, requested TTL, expected expiry, actual decommission and late or failed
cleanup without adding a second audit database.

Live job output is sent as bounded Server-Sent Event batches instead of one
browser update per line. The viewer retains only the latest 3,000 lines and
replaces that tail cleanly after a reconnect. An ownership-checked download
route streams the complete retained Kubernetes pod log in 64 KiB chunks, so a
large download is not buffered in portal memory.

Bulk decommissioning is ownership-aware. Regular users can queue only their
own cluster records; administrators can queue every recorded or observed
factory profile. The UI requires an exact `DELETE ALL` confirmation. Requests
are audited and profile-locked, and the controller dispatches at most one
deletion Job at a time.

The authenticated `Edge activity` view reads a sanitized CrowdSec summary
from the distributed edge hosts through the same forced-command Atlantis SSH
key. All users can see health and SSH/HTTP ban counts; only Factory
administrators can remove an IP decision. Administrators also get an
`MCP honeypot` tab backed by bounded Loki queries. It shows source, client,
protocol, method, tool, submitted parameters, Authorization headers and
cookies. This intentionally sensitive evidence is restricted to Factory
administrators.
Attempted passwords, HTTP headers, cookies, and query strings are never rendered.
HTTP evidence is limited to method, host, sanitized path, and status.
