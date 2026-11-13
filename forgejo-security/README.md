# Forgejo security-patched runtime

This image is a deliberately small derivative of the pinned upstream Forgejo
rootless image. It keeps Forgejo, its entrypoint and its non-root runtime
unchanged and upgrades only Alpine runtime packages for which a security fix
is available before the next Forgejo release.

The image currently updates the OpenSSH client packages from `10.2_p1-r0` to
`10.2_p1-r1`, fixing CVE-2026-123158. It does **not** claim to fix
GO-2026-6888: Forgejo must update and rebuild its compiled Go dependency on
`github.com/andybalholm/brotli` for that finding to clear.

The weekly image workflow rebuilds the derivative without cache, publishes it
to the internal Harbor project with SBOM and provenance attestations, and lets
Harbor scan it. GitOps must pin both the immutable tag and digest before the
image reaches the cluster.
