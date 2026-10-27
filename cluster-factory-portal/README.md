# Cluster Factory Portal image

Flask portal for the d00s disposable-cluster factory. Keycloak provides OIDC
identity and group claims. Kubernetes Leases serialize each profile, Jobs own
long-running operations, ConfigMaps retain audit/cluster records, and Atlantis
continues to execute the existing Ansible playbooks.

Runtime roles:

- default command: authenticated web UI and API;
- `python -m app.job_runner`: short-lived create/delete trigger;
- `python -m app.observer`: periodic sanitized inventory refresh.

The image contains no credentials. Vault Secrets Operator supplies the OIDC,
SMTP, Harbor pull, and restricted SSH material at deployment time.

The Kubernetes API integration uses the standard library with the mounted
service-account CA and token. Keeping the runtime dependency set small makes
the recurring image audit easier to review.

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
protocol, method, tool and re-redacted submitted parameters; authorization
values are never retrieved or rendered.
Attempted passwords, HTTP headers, cookies, and query strings are never rendered.
HTTP evidence is limited to method, host, sanitized path, and status.
