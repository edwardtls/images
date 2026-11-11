"""Which build settings apply to which platform.

The portal renders these rules into the New build form (so the browser can
hide what does not apply without a reload) and enforces the same rules on
submit: the server reads only the versions that apply and pins every other
component to the catalog's stable value, whatever the browser sent.
"""

PLATFORMS = ("kubernetes", "rke2", "openshift")
STORAGE_MODES = ("nfs", "ceph", "both")

# Kubernetes-family platforms share the factory GitOps platform chart
# (Argo CD, MetalLB, Traefik, cert-manager, storage, optional add-ons).
_FACTORY_GITOPS = ("kubernetes", "rke2")

# component -> (platforms, condition). A condition is ("addon", name) or
# ("storage", modes); None means the component always applies on the platform.
VERSION_RULES: dict[str, tuple[tuple[str, ...], tuple | None]] = {
    # Vanilla Kubernetes installs these itself; RKE2 and OpenShift bundle them.
    "kubernetes": (("kubernetes",), None),
    "calico": (("kubernetes",), None),
    "containerd": (("kubernetes",), None),
    "rke2": (("rke2",), None),
    "rancher_chart": (("rke2",), None),
    "openshift": (("openshift",), None),
    # OpenShift ships GitOps, ingress, certificates, metrics and monitoring.
    "argocd_chart": (_FACTORY_GITOPS, None),
    "helm_cli": (_FACTORY_GITOPS, None),
    "metallb_chart": (_FACTORY_GITOPS, None),
    "traefik_chart": (_FACTORY_GITOPS, None),
    "cert_manager_chart": (_FACTORY_GITOPS, None),
    "metrics_server_chart": (_FACTORY_GITOPS, ("addon", "metrics_server")),
    "kube_prometheus_stack_chart": (_FACTORY_GITOPS, ("addon", "monitoring")),
    "nfs_provisioner_chart": (_FACTORY_GITOPS, ("storage", ("nfs", "both"))),
    "ceph_csi": (_FACTORY_GITOPS, ("storage", ("ceph", "both"))),
}
# A component added to the catalog later behaves like the shared charts.
_DEFAULT_RULE = (_FACTORY_GITOPS, None)

# Optional add-ons offered per platform. OpenShift has its own metrics and
# monitoring stack, so it offers none.
ADDONS = {"kubernetes": ("metrics_server", "monitoring"),
          "rke2": ("metrics_server", "monitoring"),
          "openshift": ()}
STORAGE = {"kubernetes": STORAGE_MODES, "rke2": STORAGE_MODES, "openshift": ("ceph",)}


def platform_of(profile_config: dict) -> str:
    platform = profile_config.get("platform") or "kubernetes"
    return platform if platform in PLATFORMS else "kubernetes"


def rule(component: str) -> tuple[tuple[str, ...], tuple | None]:
    return VERSION_RULES.get(component, _DEFAULT_RULE)


def applies(component: str, platform: str, storage: str, addons: dict[str, bool]) -> bool:
    platforms, condition = rule(component)
    if platform not in platforms:
        return False
    if condition is None:
        return True
    kind, value = condition
    if kind == "addon":
        return bool(addons.get(value))
    return storage in value


def form_attributes(component: str) -> dict[str, str]:
    """Data attributes the build form uses to show or hide a version field."""
    platforms, condition = rule(component)
    attributes = {"data-platforms": " ".join(platforms)}
    if condition and condition[0] == "addon":
        attributes["data-addon"] = condition[1]
    elif condition:
        attributes["data-storage"] = " ".join(condition[1])
    return attributes


LABELS = {"kubernetes": "Kubernetes", "calico": "Calico", "containerd": "containerd", "rke2": "RKE2",
          "rancher_chart": "Rancher Manager chart", "openshift": "OpenShift", "argocd_chart": "Argo CD chart",
          "helm_cli": "Helm CLI", "metallb_chart": "MetalLB chart", "traefik_chart": "Traefik chart",
          "cert_manager_chart": "cert-manager chart", "metrics_server_chart": "Metrics Server chart",
          "kube_prometheus_stack_chart": "kube-prometheus-stack chart",
          "nfs_provisioner_chart": "NFS provisioner chart", "ceph_csi": "Ceph CSI"}


def label(component: str) -> str:
    return LABELS.get(component, component.replace("_", " ").title())


def storage_platforms(mode: str) -> str:
    return " ".join(platform for platform in PLATFORMS if mode in STORAGE[platform])


def initial_state(profiles: dict) -> dict:
    """What the build form shows before any script runs: the first profile with
    its default storage and add-ons, so the page never flashes other fields."""
    platform = platform_of(next(iter(profiles.values()), {}))
    storage = STORAGE[platform][0]
    addons = {"metrics_server": "metrics_server" in ADDONS[platform], "monitoring": False}
    return {"platform": platform,
            "shows": lambda platforms: platform in platforms.split(),
            "version": lambda component: applies(component, platform, storage, addons)}
