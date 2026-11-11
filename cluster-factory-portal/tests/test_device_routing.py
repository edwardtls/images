import os
import subprocess
import unittest
from unittest.mock import patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

from app import device_egress
from app.main import app
from app.security import ADMIN_GROUP

BASE = "https://factory.apps.d00s.org"
STATE = {
    "devices": [
        {"id": "apple-tv", "name": "Apple TV", "network": "Main LAN", "macs": ["c0:95:6d:7b:ff:1f"],
         "addresses": ["192.168.31.199"], "online": True, "route": "atlantis"},
        {"id": "ps5", "name": "PlayStation 5", "network": "Main LAN", "macs": ["d4:f7:d5:d3:4e:55"],
         "addresses": [], "online": False, "route": "us"},
    ],
    "path": {"gateway": "192.168.86.1", "ready": True},
}


class DeviceRoutingTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def _login(self, groups):
        with self.client.session_transaction(base_url=BASE) as session:
            session["user"] = {"sub": "admin-subject", "preferred_username": "admin", "groups": groups}
            session["csrf"] = "token"

    def test_routing_is_for_administrators_only(self):
        self._login([])
        with patch("app.security.kube.access_record",
                   return_value={"approved": True, "clusters": True, "security": True}), \
                patch("app.main.device_egress.status", return_value=STATE) as status, \
                patch("app.main.device_egress.switch") as switch:
            self.assertEqual(self.client.get("/routing", base_url=BASE).status_code, 403)
            self.assertEqual(self.client.post("/routing/apple-tv", data={"csrf": "token", "route": "us"},
                                              base_url=BASE).status_code, 403)
        status.assert_not_called()
        switch.assert_not_called()

    def test_page_lists_devices_with_their_current_route(self):
        self._login([ADMIN_GROUP])
        with patch("app.main.device_egress.status", return_value=STATE):
            response = self.client.get("/routing", base_url=BASE)
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Apple TV", page)
        self.assertIn('action="/routing/apple-tv"', page)
        self.assertIn("US path ready", page)
        self.assertIn('class="routing-device is-us"', page)

    def test_unavailable_state_is_reported(self):
        self._login([ADMIN_GROUP])
        with patch("app.main.device_egress.status", side_effect=subprocess.CalledProcessError(2, "ssh")):
            response = self.client.get("/routing", base_url=BASE)
        self.assertEqual(response.status_code, 503)
        self.assertIn("Routing state unavailable", response.get_data(as_text=True))

    def test_switch_requires_csrf_and_a_known_route(self):
        self._login([ADMIN_GROUP])
        with patch("app.main.device_egress.switch") as switch:
            self.assertEqual(self.client.post("/routing/apple-tv", data={"csrf": "bad", "route": "us"},
                                              base_url=BASE).status_code, 403)
            self.assertEqual(self.client.post("/routing/apple-tv", data={"csrf": "token", "route": "kpn"},
                                              base_url=BASE).status_code, 400)
        switch.assert_not_called()

    def test_switch_sends_only_the_id_and_direction(self):
        self._login([ADMIN_GROUP])
        with patch("app.main.device_egress.switch") as switch:
            response = self.client.post("/routing/apple-tv", data={"csrf": "token", "route": "us"},
                                        base_url=BASE)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["Location"].endswith("/routing?changed=apple-tv"))
        switch.assert_called_once_with("apple-tv", True)

    def test_module_rejects_unsafe_ids_and_builds_the_dispatch_command(self):
        for value in ("Apple-TV", "-rf", "a" * 33, "apple tv", "../x"):
            with self.assertRaises(ValueError, msg=value):
                device_egress.switch(value, True)
        completed = subprocess.CompletedProcess([], 0, stdout='{"devices": [], "path": {}}', stderr="")
        with patch("app.device_egress.subprocess.run", return_value=completed) as run:
            device_egress.switch("apple-tv", False)
        self.assertEqual(run.call_args.args[0][-4:], ["egress", "set", "apple-tv", "off"])

    def test_atlantis_failure_is_a_bad_gateway(self):
        self._login([ADMIN_GROUP])
        with patch("app.main.device_egress.switch", side_effect=subprocess.CalledProcessError(2, "ssh")):
            response = self.client.post("/routing/apple-tv", data={"csrf": "token", "route": "us"},
                                        base_url=BASE)
        self.assertEqual(response.status_code, 502)


if __name__ == "__main__":
    unittest.main()
