import os
import unittest
from unittest.mock import patch

os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")

from app import documentation


class DocumentationTests(unittest.TestCase):
    def configmap(self, body="# Safe\n\nOperational text"):
        return {"data": {
            "catalog.yaml": """documents:
  - id: vault-transit
    title: Vault Transit
    summary: Unseal provider
    category: Secrets
    location: Atlantis
    file: vault-transit.md
    source: d00s/factory-docs/content/vault-transit.md
""",
            "vault-transit.md": body,
        }}

    @patch("app.documentation._configmap")
    def test_catalog_and_document_are_loaded_from_one_configmap(self, configmap):
        configmap.return_value = self.configmap()
        self.assertEqual(documentation.catalog()[0]["id"], "vault-transit")
        self.assertIn("<h1>Safe</h1>", str(documentation.document("vault-transit")["html"]))

    @patch("app.documentation._configmap")
    def test_rendering_escapes_html_and_blocks_harmful_links(self, configmap):
        configmap.return_value = self.configmap(
            '<script>alert(1)</script>\n\n[x](javascript:alert(1))')
        rendered = str(documentation.document("vault-transit")["html"])
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("javascript:", rendered)

    @patch("app.documentation._configmap")
    def test_unknown_or_unsafe_document_id_is_not_resolved(self, configmap):
        configmap.return_value = self.configmap()
        self.assertIsNone(documentation.document("../secret"))
        self.assertIsNone(documentation.document("missing"))


if __name__ == "__main__":
    unittest.main()
