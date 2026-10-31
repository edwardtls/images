import json
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("WORKER_IMAGE", "test.invalid/worker:test")

from app import ai_control


class AIControlTests(unittest.TestCase):
    @patch("app.ai_control.kube.api")
    def test_status_is_read_from_kubernetes(self, api):
        def response(method, path, *args, **kwargs):
            if "configmaps" in path:
                return {"data": {"state.json": json.dumps({"mode": "off", "last_run": None})}}
            if path.endswith("/deployments/d00s-ai-model"):
                return {"spec": {"replicas": 0}, "status": {}}
            if "/jobs" in path:
                return {"items": []}
            raise AssertionError(path)
        api.side_effect = response
        result = ai_control.command("status")
        self.assertEqual(result["mode"], "off")
        self.assertEqual(result["model"], "stopped")

    def test_unknown_action_is_rejected_locally(self):
        with self.assertRaises(ValueError):
            ai_control.command("shell")


if __name__ == "__main__":
    unittest.main()
