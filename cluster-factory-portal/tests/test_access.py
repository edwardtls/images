import unittest
import os
from unittest.mock import patch

from flask import Flask, session
from werkzeug.exceptions import Forbidden

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")

from app import kube
from app.security import (can_manage_clusters, can_view_security, current_user,
                          require_clusters, require_security)


class FactoryAccessTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-only"

    def _session(self, groups):
        session["user"] = {
            "sub": "9d8fc7ca-13de-4c96-82b3-1eb2872ef202",
            "preferred_username": "engineer",
            "groups": list(groups),
        }

    def test_unapproved_user_is_denied_and_session_is_cleared(self):
        with self.app.test_request_context("/"):
            self._session([])
            with patch("app.security.kube.access_record", return_value=None):
                with self.assertRaises(Forbidden):
                    current_user()
            self.assertNotIn("user", session)

    def test_approved_user_has_no_implicit_capabilities(self):
        with self.app.test_request_context("/"):
            self._session([])
            with patch("app.security.kube.access_record", return_value={
                "approved": True, "clusters": False, "security": False}):
                user = current_user()
                self.assertFalse(can_manage_clusters(user))
                self.assertFalse(can_view_security(user))
                with self.assertRaises(Forbidden):
                    require_clusters()
                with self.assertRaises(Forbidden):
                    require_security()

    def test_cluster_and_security_entitlements_are_independent(self):
        with self.app.test_request_context("/"):
            cluster_groups = set()
            self._session(cluster_groups)
            with patch("app.security.kube.access_record", return_value={
                "approved": True, "clusters": True, "security": False}):
                self.assertEqual(require_clusters()["preferred_username"], "engineer")
                with self.assertRaises(Forbidden):
                    require_security()

        with self.app.test_request_context("/"):
            security_groups = set()
            self._session(security_groups)
            with patch("app.security.kube.access_record", return_value={
                "approved": True, "clusters": False, "security": True}):
                self.assertEqual(require_security()["preferred_username"], "engineer")
                with self.assertRaises(Forbidden):
                    require_clusters()

    def test_administrator_inherits_all_capabilities(self):
        with self.app.test_request_context("/"):
            admin_groups = {"factory-admins"}
            self._session(admin_groups)
            self.assertTrue(can_manage_clusters(current_user()))
            self.assertTrue(can_view_security(current_user()))


class AccessRegistryTests(unittest.TestCase):
    @patch("app.kube.api")
    def test_new_identity_creates_pending_record_without_capabilities(self, api):
        api.side_effect = [kube.KubeError(404, "not found"), None]
        record = kube.ensure_access_request({
            "sub": "new-user-id", "preferred_username": "new-user",
            "email": "new-user@example.test",
        }, "192.0.2.10")
        self.assertFalse(record["approved"])
        self.assertFalse(record["clusters"])
        self.assertFalse(record["security"])
        payload = api.call_args_list[1].args[2]
        self.assertEqual(payload["metadata"]["labels"]["factory.d00s.org/status"], "pending")

    @patch("app.kube.api")
    def test_revoking_approval_also_revokes_all_capabilities(self, api):
        api.side_effect = [
            {"metadata": {"name": kube.access_resource_name("user-id")},
             "data": {"record.json": '{"schema":1,"subject":"user-id","username":"engineer","approved":true,"clusters":true,"security":true}'}},
            None,
        ]
        changed = kube.update_access_record(
            kube.access_resource_name("user-id"),
            approved=False,
            clusters=True,
            security=True,
            administrator={"preferred_username": "admin"},
        )
        self.assertFalse(changed["approved"])
        self.assertFalse(changed["clusters"])
        self.assertFalse(changed["security"])
        patch_payload = api.call_args_list[1].args[2]
        self.assertEqual(patch_payload["metadata"]["labels"]["factory.d00s.org/status"], "pending")


if __name__ == "__main__":
    unittest.main()
