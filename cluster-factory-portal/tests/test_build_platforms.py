import os
import re
import unittest
from unittest.mock import patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

from app import build_options
from app.main import app
from app.security import ADMIN_GROUP

BASE = "https://factory.apps.d00s.org"
PROFILES = {"k8s": {"domain": "k8s.d00s.org"},
            "ocp": {"domain": "ocp.d00s.org", "platform": "openshift", "admin_only": True},
            "rke2": {"domain": "rke2.d00s.org", "platform": "rke2"}}
COMPONENTS = ["kubernetes", "calico", "containerd", "argocd_chart", "metallb_chart", "traefik_chart",
              "cert_manager_chart", "metrics_server_chart", "kube_prometheus_stack_chart",
              "nfs_provisioner_chart", "ceph_csi", "openshift", "rke2", "rancher_chart", "helm_cli"]
STABLE = {name: f"{name}-stable" for name in COMPONENTS} | {"rke2": "v1.36.6+rke2r1"}
VERSIONS = {name: [{"value": STABLE[name], "tested": True}, {"value": f"{name}-candidate", "tested": False}]
            for name in COMPONENTS}


def visible(platform, storage="nfs", **addons):
    return {name for name in COMPONENTS if build_options.applies(name, platform, storage, addons)}


class RuleTests(unittest.TestCase):
    def test_openshift_needs_only_its_release(self):
        self.assertEqual(visible("openshift", "ceph", metrics_server=True, monitoring=True), {"openshift"})

    def test_rke2_drops_what_it_bundles_and_vanilla_drops_rke2_and_openshift(self):
        rke2 = visible("rke2", "both", metrics_server=True, monitoring=True)
        vanilla = visible("kubernetes", "both", metrics_server=True, monitoring=True)
        self.assertFalse({"kubernetes", "calico", "containerd", "openshift"} & rke2)
        self.assertTrue({"rke2", "rancher_chart", "argocd_chart"} <= rke2)
        self.assertFalse({"rke2", "rancher_chart", "openshift"} & vanilla)
        self.assertTrue({"kubernetes", "calico", "containerd", "argocd_chart"} <= vanilla)

    def test_add_on_and_storage_charts_follow_the_choices(self):
        self.assertNotIn("kube_prometheus_stack_chart", visible("kubernetes"))
        self.assertIn("kube_prometheus_stack_chart", visible("kubernetes", monitoring=True))
        self.assertEqual({"nfs_provisioner_chart", "ceph_csi"} & visible("kubernetes", "nfs"), {"nfs_provisioner_chart"})
        self.assertEqual({"nfs_provisioner_chart", "ceph_csi"} & visible("kubernetes", "ceph"), {"ceph_csi"})

    def test_unknown_platform_and_new_components_fall_back_safely(self):
        self.assertEqual(build_options.platform_of({"platform": "<script>"}), "kubernetes")
        self.assertTrue(build_options.applies("future_chart", "rke2", "nfs", {}))
        self.assertFalse(build_options.applies("future_chart", "openshift", "ceph", {}))


class BuildFormTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        with self.client.session_transaction(base_url=BASE) as session:
            session["user"] = {"sub": "admin-subject", "preferred_username": "admin", "groups": [ADMIN_GROUP]}
            session["csrf"] = "token"
        for target, value in (("app.main.kube.reconcile", None), ("app.main.visible_records", []),
                              ("app.main.normalized_inventory", {"clusters": {}}),
                              ("app.main.kube.active_jobs", []), ("app.main.kube.quota_for", 2),
                              ("app.main.kube.visible_profiles", PROFILES), ("app.main.kube.profiles", PROFILES),
                              ("app.main.kube.versions", VERSIONS), ("app.main.kube.cluster_records", []),
                              ("app.main.kube.inventory", {"clusters": {}}),
                              ("app.main.kube.policy", {"max_ttl_regular": "7d"}),
                              ("app.security.kube.access_record", None)):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.submit = patch("app.main.kube.submit", return_value="job-1").start()
        self.addCleanup(patch.stopall)

    def field(self, page, component):
        return re.search(rf'<label data-version[^>]*>[^<]*<select name="version_{component}"[^>]*>', page).group(0)

    def test_form_starts_with_only_the_first_profile_fields(self):
        page = self.client.get("/build", base_url=BASE).get_data(as_text=True)
        for component in ("kubernetes", "calico", "argocd_chart", "nfs_provisioner_chart"):
            self.assertNotIn(" hidden", self.field(page, component), component)
        for component in ("openshift", "rke2", "rancher_chart", "kube_prometheus_stack_chart", "ceph_csi"):
            self.assertIn("hidden", self.field(page, component), component)
            self.assertIn("disabled", self.field(page, component), component)
        self.assertIn('data-platforms="kubernetes rke2" data-addon="monitoring"',
                      self.field(page, "kube_prometheus_stack_chart"))
        self.assertIn('<option value="nfs" data-platforms="kubernetes rke2">', page)
        self.assertIn("Argo CD chart", page)

    def post(self, **fields):
        data = {"csrf": "token", "ttl": "24h", "control_planes": "3", "workers": "3"} | fields
        response = self.client.post("/build", data=data, base_url=BASE)
        return response, (self.submit.call_args.args[1] if self.submit.called else None)

    def test_openshift_ignores_and_pins_every_other_component(self):
        tampered = {f"version_{name}": "not-a-version" for name in COMPONENTS if name != "openshift"}
        response, request = self.post(profile="ocp", storage="ceph", version_openshift="openshift-candidate",
                                      monitoring="on", metrics_server="on", **tampered)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(request["versions"]["openshift"], "openshift-candidate")
        self.assertEqual(request["argo_chart_version"], STABLE["argocd_chart"])
        self.assertEqual(request["versions"]["kube_prometheus_stack_chart"], STABLE["kube_prometheus_stack_chart"])
        self.assertEqual(request["addons"], {"monitoring": False, "metrics_server": False, "test_nginx": True})
        self.assertNotIn("rke2", request["versions"])

    def test_openshift_rejects_storage_it_cannot_use(self):
        response, request = self.post(profile="ocp", storage="nfs")
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(request)

    def test_rke2_uses_its_choices_and_pins_bundled_components(self):
        response, request = self.post(profile="rke2", storage="nfs", version_rke2="rke2-candidate",
                                      version_rancher_chart="rancher_chart-candidate",
                                      version_argocd_chart="argocd_chart-candidate",
                                      version_calico="not-a-version", version_containerd="not-a-version",
                                      **{f"version_{n}": STABLE[n] for n in ("helm_cli", "metallb_chart",
                                         "traefik_chart", "cert_manager_chart", "nfs_provisioner_chart")})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(request["versions"]["rancher_chart"], "rancher_chart-candidate")
        self.assertEqual(request["argo_chart_version"], "argocd_chart-candidate")
        self.assertEqual(request["calico_version"], STABLE["calico"])
        self.assertEqual(request["kubernetes_version"], "rke2-candidate")
        self.assertNotIn("openshift", request["versions"])

    def test_vanilla_still_validates_every_version_that_applies(self):
        response, request = self.post(profile="k8s", storage="nfs", version_kubernetes="not-a-version")
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(request)

    def test_monitoring_chart_is_read_only_when_monitoring_is_chosen(self):
        applying = {f"version_{n}": STABLE[n] for n in visible("kubernetes", "nfs")}
        response, request = self.post(profile="k8s", storage="nfs", **applying,
                                      version_kube_prometheus_stack_chart="kube_prometheus_stack_chart-candidate")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(request["versions"]["kube_prometheus_stack_chart"], STABLE["kube_prometheus_stack_chart"])
        self.submit.reset_mock()
        response, request = self.post(profile="k8s", storage="nfs", monitoring="on", **(applying | {
            "version_kube_prometheus_stack_chart": "kube_prometheus_stack_chart-candidate"}))
        self.assertEqual(response.status_code, 303)
        self.assertEqual(request["versions"]["kube_prometheus_stack_chart"], "kube_prometheus_stack_chart-candidate")
        self.assertTrue(request["addons"]["monitoring"])


if __name__ == "__main__":
    unittest.main()
