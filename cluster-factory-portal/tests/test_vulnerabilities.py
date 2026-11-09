import json
import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

import psycopg

from app import vulnerabilities
from app.main import app
from app.security import ADMIN_GROUP

BASE = "https://factory.apps.d00s.org"
OVERVIEW = '{"generated_at": "2026-11-07T05:50:00Z", "systems": [], "vulnerabilities": []}'


class FakeProcess:
    def __init__(self, lines):
        self.stdout = iter(lines)

    def kill(self):
        pass

    def wait(self):
        return 0


def line(kind, identifier="", document=None, **extra):
    return json.dumps({"kind": kind, "id": identifier, "document": document, **extra}) + "\n"


class VulnerabilityPageTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def _login(self, groups):
        with self.client.session_transaction(base_url=BASE) as session:
            session["user"] = {"sub": "admin-subject", "preferred_username": "admin", "groups": groups}

    def test_pages_and_api_are_for_administrators_only(self):
        self._login([])
        with patch("app.security.kube.access_record",
                   return_value={"approved": True, "clusters": True, "security": True}):
            for path in ("/security/vulnerabilities", "/api/security/vulnerabilities",
                         "/api/security/vulnerabilities/status"):
                self.assertEqual(self.client.get(path, base_url=BASE).status_code, 403, path)

    def test_documents_are_served_from_the_database_unchanged(self):
        self._login([ADMIN_GROUP])
        with patch("app.vulnerabilities._document", return_value=OVERVIEW) as document:
            response = self.client.get("/api/security/vulnerabilities", base_url=BASE)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertEqual(response.get_data(as_text=True), OVERVIEW)
        document.assert_called_once_with("overview", "")

    def test_detail_requests_are_validated(self):
        self._login([ADMIN_GROUP])
        with patch("app.vulnerabilities._document", return_value='{"id": "d00s:vault:vault"}') as document:
            self.assertEqual(self.client.get("/api/security/vulnerabilities/system/d00s:vault:vault",
                                             base_url=BASE).status_code, 200)
            for path in ("/api/security/vulnerabilities/shell/x", "/api/security/vulnerabilities/system/..%2fetc",
                         "/api/security/vulnerabilities/system/-rf"):
                self.assertEqual(self.client.get(path, base_url=BASE).status_code, 404, path)
        document.assert_called_once_with("system", "d00s:vault:vault")

    def test_missing_items_and_outages(self):
        self._login([ADMIN_GROUP])
        with patch("app.vulnerabilities._document", side_effect=vulnerabilities.NotFound("gone")):
            self.assertEqual(self.client.get("/api/security/vulnerabilities/system/gone",
                                             base_url=BASE).status_code, 404)
        with patch("app.vulnerabilities._document", side_effect=psycopg.OperationalError("down")):
            self.assertEqual(self.client.get("/api/security/vulnerabilities", base_url=BASE).status_code, 503)
        with patch("app.vulnerabilities.status", side_effect=vulnerabilities.NotFound("none")):
            self.assertEqual(self.client.get("/api/security/vulnerabilities/status",
                                             base_url=BASE).status_code, 503)

    def test_status_is_small(self):
        self._login([ADMIN_GROUP])
        status = {"generated_at": "2026-11-07T05:50:00Z", "imported_at": "2026-11-07T05:55:00Z"}
        with patch("app.vulnerabilities.status", return_value=status):
            response = self.client.get("/api/security/vulnerabilities/status", base_url=BASE)
        self.assertEqual(json.loads(response.data), status)

    def test_page_renders_the_view(self):
        self._login([ADMIN_GROUP])
        response = self.client.get("/security/vulnerabilities/systems/d00s:forgejo:forgejo", base_url=BASE)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'data-view="system"', response.data)
        self.assertIn(b'/static/vulns.js', response.data)
        self.assertEqual(self.client.get("/security/vulnerabilities/other/x", base_url=BASE).status_code, 404)

    def test_vulnerabilities_are_a_view_of_the_security_page(self):
        self._login([ADMIN_GROUP])
        page = self.client.get("/security/vulnerabilities", base_url=BASE).get_data(as_text=True)
        self.assertIn('data-view="vulns" class="active"', page)
        self.assertIn('<div id="vulns-pane">', page)
        self.assertIn('data-window="today" aria-live="polite" hidden data-empty', page)
        with patch("app.main.security_store.edge_status", side_effect=RuntimeError("down")):
            edge = self.client.get("/security?view=edge", base_url=BASE).get_data(as_text=True)
        self.assertIn('<div id="vulns-pane" hidden>', edge)
        self.assertIn('/static/vulns.js', edge)


class VulnerabilityImportTests(unittest.TestCase):
    def _export(self, lines):
        with patch("app.vulnerabilities.subprocess.Popen", return_value=FakeProcess(lines)):
            return list(vulnerabilities._export())

    def test_export_yields_every_document(self):
        items = self._export([line("overview", document={"generated_at": "T1"}),
                              line("system", "d00s:vault:vault", {"id": "d00s:vault:vault"}),
                              line("vulnerability", "CVE-2026-1", {"id": "CVE-2026-1"}),
                              json.dumps({"kind": "end", "generated_at": "T1"}) + "\n"])
        self.assertEqual([(kind, identifier) for kind, identifier, _ in items],
                         [("overview", ""), ("system", "d00s:vault:vault"), ("vulnerability", "CVE-2026-1")])

    def test_export_rejects_incomplete_or_changed_reports(self):
        overview = line("overview", document={"generated_at": "T1"})
        for lines in ([overview],
                      [overview, json.dumps({"kind": "end", "generated_at": "T2"}) + "\n"],
                      [overview, json.dumps({"kind": "end", "generated_at": None}) + "\n"],
                      [overview, line("shell", "x", {})],
                      [overview, line("system", "../etc", {})],
                      [line("system", "a", {}), json.dumps({"kind": "end", "generated_at": "T1"}) + "\n"]):
            with self.assertRaises(RuntimeError, msg=lines):
                self._export(lines)

    def test_an_imported_report_is_not_imported_again(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchone.return_value = ("T1",)
        with patch("app.vulnerabilities.edge_security._command", return_value={"generated_at": "T1"}), \
                patch("app.vulnerabilities.security_store._connect", return_value=connection), \
                patch("app.vulnerabilities._export") as export:
            self.assertEqual(vulnerabilities.collect(), {"vulnerabilities": "unchanged"})
        export.assert_not_called()
        self.assertFalse(any("DELETE" in str(call) for call in connection.execute.call_args_list))


if __name__ == "__main__":
    unittest.main()
