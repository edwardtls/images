import os
import unittest
from unittest.mock import patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")

from app import kube

PROFILES = {"dev": {"domain": "dev.example"}, "ocp": {"domain": "ocp.example", "admin_only": True}}


class OpenShiftProfileTests(unittest.TestCase):
    def test_admin_only_profile_is_hidden_from_regular_users(self):
        with patch.object(kube, "profiles", return_value=PROFILES):
            self.assertEqual(set(kube.visible_profiles(False)), {"dev"})
            self.assertEqual(set(kube.visible_profiles(True)), {"dev", "ocp"})

    def test_accepts_the_supported_shape(self):
        self.assertIsNone(kube.openshift_request_error(3, 2, "ceph", 672))
        self.assertIsNone(kube.openshift_request_error(3, 6, "ceph", 24))

    def test_rejects_unsupported_shapes(self):
        for request in ((1, 3, "ceph", 24), (5, 3, "ceph", 24), (3, 1, "ceph", 24),
                        (3, 3, "nfs", 24), (3, 3, "both", 24), (3, 3, "ceph", 673)):
            self.assertIsNotNone(kube.openshift_request_error(*request), request)


if __name__ == "__main__":
    unittest.main()
