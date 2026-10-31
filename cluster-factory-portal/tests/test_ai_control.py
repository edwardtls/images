import json
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("EDGE_SSH_TARGET", "edward@192.0.2.10")

from app import ai_control


class AIControlTests(unittest.TestCase):
    @patch("app.ai_control.subprocess.run")
    def test_status_uses_forced_ssh_command(self, run):
        run.return_value.stdout = json.dumps({"mode": "off", "model": "inactive"})
        result = ai_control.command("status")
        self.assertEqual(result["mode"], "off")
        argv = run.call_args.args[0]
        self.assertEqual(argv[-2:], ["ai", "status"])
        self.assertIn("BatchMode=yes", argv)

    def test_unknown_action_is_rejected_locally(self):
        with self.assertRaises(ValueError):
            ai_control.command("shell")


if __name__ == "__main__":
    unittest.main()
