import json
import os
import subprocess
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

from app import ps5_reports
from app.main import app
from app.security import ADMIN_GROUP

BASE = "https://factory.apps.d00s.org"
MARKDOWN = "# PS5 network report — 2026-11-10\n\n| Count | Name |\n| ---: | --- |\n| 2 | `example.test` |"


class Ps5ReportTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def _login(self, groups):
        with self.client.session_transaction(base_url=BASE) as session:
            session["user"] = {"sub": "subject", "preferred_username": "admin", "groups": groups}

    def test_page_is_administrator_only(self):
        self._login([])
        with patch("app.security.kube.access_record",
                   return_value={"approved": True, "clusters": True, "security": True}):
            self.assertEqual(self.client.get("/ps5", base_url=BASE).status_code, 403)

    def test_page_renders_latest_report_and_navigation_tab(self):
        self._login([ADMIN_GROUP])
        with patch("app.main.ps5_reports.report", return_value={
                "date": "2026-11-10", "html": ps5_reports.documentation.render_markdown(MARKDOWN)}):
            response = self.client.get("/ps5", base_url=BASE)
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/ps5">PS5 Network</a>', page)
        self.assertIn("example.test", page)
        self.assertIn('value="2026-11-10"', page)

    def test_date_is_validated_before_ssh(self):
        self._login([ADMIN_GROUP])
        with patch("app.main.ps5_reports.report") as report:
            response = self.client.get("/ps5?date=../../etc/passwd", base_url=BASE)
        self.assertEqual(response.status_code, 400)
        report.assert_not_called()

    @patch("app.ps5_reports.subprocess.run")
    def test_report_uses_forced_command_and_escapes_html(self, run):
        run.return_value = MagicMock(stdout=json.dumps({
            "date": "2026-11-10", "markdown": MARKDOWN + "\n\n<script>alert(1)</script>"}))
        report = ps5_reports.report("2026-11-10")
        command = run.call_args.args[0]
        self.assertEqual(command[-3:], ["ps5", "report", "2026-11-10"])
        self.assertNotIn("<script>", str(report["html"]))
        self.assertIn("&lt;script&gt;", str(report["html"]))

    @patch("app.ps5_reports.subprocess.run")
    def test_missing_and_invalid_reports_are_rejected(self, run):
        run.return_value = MagicMock(stdout='{"error":"not_found"}')
        with self.assertRaises(ps5_reports.NotFound):
            ps5_reports.report("2026-11-09")
        for output in ('{}', '{"date":"bad","markdown":"x"}', 'not-json'):
            run.return_value = MagicMock(stdout=output)
            with self.assertRaises((RuntimeError, json.JSONDecodeError)):
                ps5_reports.report("latest")
        with self.assertRaises(ValueError):
            ps5_reports.report("../latest")


if __name__ == "__main__":
    unittest.main()
