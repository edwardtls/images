import os
import unittest

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

from app.main import app

BASE = "https://factory.apps.d00s.org"


class SessionExpiryTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_page_load_without_session_returns_to_main_page(self):
        for path in ("/dashboard", "/ps5", "/routing", "/security"):
            response = self.client.get(path, base_url=BASE, headers={"Sec-Fetch-Mode": "navigate"})
            self.assertEqual(response.status_code, 303, path)
            self.assertEqual(response.headers["Location"], "/?expired=1")

    def test_form_post_without_session_returns_to_main_page(self):
        response = self.client.post("/ps5/generate", base_url=BASE, data={"date": "2026-11-15"})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], "/?expired=1")

    def test_background_request_keeps_401_with_marker(self):
        for path, headers in (("/api/ps5/pane", {}), ("/dashboard", {"Sec-Fetch-Mode": "cors"})):
            response = self.client.get(path, base_url=BASE, headers=headers)
            self.assertEqual(response.status_code, 401, path)
            self.assertEqual(response.headers["X-Factory-Session"], "expired")

    def test_main_page_explains_the_expired_session(self):
        page = self.client.get("/?expired=1", base_url=BASE).get_data(as_text=True)
        self.assertIn("Your session has ended.", page)
        self.assertIn('href="/login"', page)
        self.assertNotIn("Your session has ended.", self.client.get("/", base_url=BASE).get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
