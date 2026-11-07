import json
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

from app import vulnerabilities
from app.main import app
from app.security import ADMIN_GROUP

BASE = "https://factory.apps.d00s.org"
OVERVIEW = {"generated_at": "2026-11-07T05:50:00Z", "systems": [], "vulnerabilities": []}


class VulnerabilityPageTests(unittest.TestCase):
    def setUp(self):
        vulnerabilities._cache.clear()
        self.client = app.test_client()

    def _login(self, groups):
        with self.client.session_transaction(base_url=BASE) as session:
            session["user"] = {"sub": "admin-subject", "preferred_username": "admin", "groups": groups}

    def test_pages_and_api_are_for_administrators_only(self):
        self._login([])
        with patch("app.security.kube.access_record",
                   return_value={"approved": True, "clusters": True, "security": True}):
            for path in ("/security/vulnerabilities", "/api/security/vulnerabilities"):
                self.assertEqual(self.client.get(path, base_url=BASE).status_code, 403, path)

    def test_overview_is_read_through_the_dispatcher(self):
        self._login([ADMIN_GROUP])
        with patch("app.vulnerabilities.edge_security._command", return_value=OVERVIEW) as command:
            response = self.client.get("/api/security/vulnerabilities", base_url=BASE)
            self.client.get("/api/security/vulnerabilities", base_url=BASE)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.data), OVERVIEW)
        command.assert_called_once_with("vulns", "overview")

    def test_detail_requests_are_validated(self):
        self._login([ADMIN_GROUP])
        with patch("app.vulnerabilities.edge_security._command", return_value={"id": "CVE-2026-1"}) as command:
            self.assertEqual(self.client.get("/api/security/vulnerabilities/vulnerability/CVE-2026-1",
                                             base_url=BASE).status_code, 200)
            for path in ("/api/security/vulnerabilities/shell/x", "/api/security/vulnerabilities/system/..%2fetc",
                         "/api/security/vulnerabilities/system/-rf"):
                self.assertEqual(self.client.get(path, base_url=BASE).status_code, 404, path)
        command.assert_called_once_with("vulns", "vulnerability", "CVE-2026-1")

    def test_missing_items_and_outages(self):
        self._login([ADMIN_GROUP])
        with patch("app.vulnerabilities.edge_security._command", return_value={"error": "not_found"}):
            self.assertEqual(self.client.get("/api/security/vulnerabilities/system/gone",
                                             base_url=BASE).status_code, 404)
        with patch("app.vulnerabilities.edge_security._command", side_effect=OSError("ssh failed")):
            self.assertEqual(self.client.get("/api/security/vulnerabilities", base_url=BASE).status_code, 503)

    def test_page_renders_the_view(self):
        self._login([ADMIN_GROUP])
        response = self.client.get("/security/vulnerabilities/systems/worker10.d00s.org", base_url=BASE)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'data-view="system"', response.data)
        self.assertIn(b'/static/vulns.js', response.data)
        self.assertEqual(self.client.get("/security/vulnerabilities/other/x", base_url=BASE).status_code, 404)


if __name__ == "__main__":
    unittest.main()
