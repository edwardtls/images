import os
import re
import unittest
from unittest.mock import patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

from app.main import app
from app.security import ADMIN_GROUP

BASE = "https://factory.apps.d00s.org"
PROFILES = {"k8s": {"domain": "k8s.d00s.org"},
            "ocp": {"domain": "ocp.d00s.org", "platform": "openshift", "admin_only": True},
            "rancher": {"domain": "rancher.d00s.org", "platform": "rancher"}}
VERSIONS = {"kubernetes": [{"value": "1.37.0", "tested": True}],
            "openshift": [{"value": "4.20.1", "tested": True}],
            "rke2": [{"value": "v1.36.6+rke2r1", "tested": False}],
            "rancher_chart": [{"value": "2.15.3", "tested": False}]}


def pane(page, name):
    return re.search(rf'<section class="subpane" role="tabpanel" id="pane-{name}"[^>]*>', page).group(0)


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        for target, value in (("app.main.kube.reconcile", None), ("app.main.visible_records", []),
                              ("app.main.normalized_inventory", {"clusters": {}}),
                              ("app.main.kube.active_jobs", []), ("app.main.kube.quota_for", 2),
                              ("app.main.kube.visible_profiles", PROFILES),
                              ("app.main.kube.versions", VERSIONS),
                              ("app.main.device_egress.status", {"devices": [], "path": {"ready": True}}),
                              ("app.main.device_egress_store.history", None),
                              ("app.main.ps5_reports.available", []),
                              ("app.main.ps5_reports.report", {"date": "2026-11-11", "html": ""})):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def login(self, groups=(), access=None):
        with self.client.session_transaction(base_url=BASE) as session:
            session["user"] = {"sub": "user-subject", "preferred_username": "user", "groups": list(groups)}
            session["csrf"] = "token"
        patcher = patch("app.security.kube.access_record", return_value=access)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_each_cluster_url_opens_its_sub_tab_with_the_others_hidden(self):
        self.login([ADMIN_GROUP])
        for path, active in (("/clusters", "list"), ("/build", "build"), ("/howto", "howto")):
            page = self.client.get(path, base_url=BASE).get_data(as_text=True)
            self.assertIn(f'id="tab-{active}" aria-controls="pane-{active}" aria-selected="true"', page, path)
            for name in ("list", "build", "howto"):
                self.assertEqual(" hidden" in pane(page, name), name != active, (path, name))
            self.assertIn('<a href="/clusters" class="active" aria-current="page">Clusters</a>', page)
            self.assertNotIn('href="/build">New build</a><a', page.split("</nav>")[0])  # no top-level New build

    def test_build_labels_openshift_and_vanilla_kubernetes(self):
        self.login([ADMIN_GROUP])
        page = self.client.get("/build", base_url=BASE).get_data(as_text=True)
        self.assertIn('data-platform="openshift">OCP · OpenShift · ocp.d00s.org</option>', page)
        self.assertIn('data-platform="kubernetes">K8S · Vanilla Kubernetes · k8s.d00s.org</option>', page)
        self.assertIn('data-platform="rancher">RANCHER · Rancher / RKE2 · rancher.d00s.org</option>', page)
        self.assertIn("Rancher uses RKE2 plus Rancher Manager", page)

    def test_users_without_cluster_access_get_only_how_it_works(self):
        self.login(access={"approved": True, "clusters": False, "security": False})
        with patch("app.main.visible_records") as records:
            page = self.client.get("/howto", base_url=BASE).get_data(as_text=True)
            self.assertEqual(self.client.get("/clusters", base_url=BASE).status_code, 403)
            self.assertEqual(self.client.get("/build", base_url=BASE).status_code, 403)
        records.assert_not_called()  # no cluster data is loaded for them
        self.assertNotIn('id="pane-list"', page)
        self.assertNotIn('id="pane-build"', page)
        self.assertIn('<a href="/howto" class="active" aria-current="page">How it works</a>', page)

    def test_home_network_is_for_administrators_only(self):
        self.login(access={"approved": True, "clusters": True, "security": True})
        for path in ("/routing", "/ps5"):
            self.assertEqual(self.client.get(path, base_url=BASE).status_code, 403, path)
        self.assertNotIn("Home network", self.client.get("/dashboard", base_url=BASE).get_data(as_text=True))

    def test_home_network_tabs_and_isolated_failures(self):
        self.login([ADMIN_GROUP])
        with patch("app.main.device_egress.status", side_effect=OSError("down")):
            routing = self.client.get("/routing", base_url=BASE)
            ps5 = self.client.get("/ps5", base_url=BASE)
        self.assertEqual(routing.status_code, 503)  # the visible pane failed
        self.assertEqual(ps5.status_code, 200)      # the PS5 pane is fine; routing shows its own warning
        self.assertIn("Routing state unavailable", ps5.get_data(as_text=True))
        self.assertIn('id="tab-ps5" aria-controls="pane-ps5" aria-selected="true"', ps5.get_data(as_text=True))

    def test_report_date_is_ignored_on_the_routing_tab_and_validated_on_the_ps5_tab(self):
        self.login([ADMIN_GROUP])
        self.assertEqual(self.client.get("/routing?date=../../etc", base_url=BASE).status_code, 200)
        self.assertEqual(self.client.get("/ps5?date=../../etc", base_url=BASE).status_code, 400)


if __name__ == "__main__":
    unittest.main()
