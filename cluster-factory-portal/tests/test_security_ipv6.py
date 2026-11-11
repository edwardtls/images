import os
import unittest
from unittest.mock import patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

from app.main import app
from app.security import ADMIN_GROUP

BASE = "https://factory.apps.d00s.org"
IPV6 = "2001:db8:85a3::8a2e:370:7334"


def edge_status(*decisions):
    return {
        "active_bans": len(decisions), "total_active_bans": len(decisions),
        "ssh_bans": len(decisions), "rdp_bans": 0, "http_bans": 0, "top_countries": [],
        "decisions": list(decisions), "findings_truncated": False, "sensors": [],
        "bouncers": [], "observed_at": None,
        "trend": {"bucket_seconds": 3600, "points": [],
                  "totals": {"total": 0, "ssh": 0, "rdp": 0, "http": 0}},
    }


class SecurityIPv6Tests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        with self.client.session_transaction(base_url=BASE) as session:
            session["user"] = {"sub": "admin-subject", "preferred_username": "admin",
                               "groups": [ADMIN_GROUP]}
            session["csrf"] = "token"

    def test_ipv6_finding_is_listed_with_a_removal_action(self):
        decision = {"ip": IPV6, "service": "SSH", "sensor": "edge-atlantis", "active": True,
                    "scenario": "d00s/cowrie-first-credential", "duration": "503h"}
        with patch("app.main.security_store.edge_status", return_value=edge_status(decision)):
            response = self.client.get("/security", base_url=BASE)
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'<span class="mono" data-label="Address">{IPV6}</span>', page)
        self.assertIn(f'action="/security/bans/{IPV6}/delete"', page)

    def test_ipv6_ban_removal_is_normalized_and_forwarded(self):
        expanded = "2001:0DB8:85A3:0000:0000:8A2E:0370:7334"
        with patch("app.main.edge_security.delete") as delete:
            response = self.client.post(f"/security/bans/{expanded}/delete",
                                        data={"csrf": "token"}, base_url=BASE)
        self.assertEqual(response.status_code, 303)
        delete.assert_called_once_with(IPV6)
        self.assertTrue(response.headers["Location"].endswith(
            "/security?removed=" + IPV6.replace(":", "%3A")))

    def test_invalid_addresses_are_rejected_before_the_edge_is_called(self):
        with patch("app.main.edge_security.delete") as delete:
            for value in ("2001:db8::g", "2001:db8::1%25eth0", "-rf"):
                response = self.client.post(f"/security/bans/{value}/delete",
                                            data={"csrf": "token"}, base_url=BASE)
                self.assertEqual(response.status_code, 400, value)
        delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
