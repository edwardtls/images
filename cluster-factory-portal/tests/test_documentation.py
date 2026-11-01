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

    @patch("app.documentation._configmap")
    def test_child_documents_are_linked_to_their_parent(self, configmap):
        body = self.configmap()
        body["data"]["catalog.yaml"] += """  - id: vault-schema
    title: Vault storage schema
    summary: Raft data ownership
    category: Secrets
    location: Vault
    file: vault-schema.md
    source: d00s/factory-docs/content/vault-schema.md
    parent: vault-transit
"""
        body["data"]["vault-schema.md"] = "# Storage schema"
        configmap.return_value = body
        parent = documentation.document("vault-transit")
        child = documentation.document("vault-schema")
        self.assertEqual(parent["children"][0]["id"], "vault-schema")
        self.assertEqual(child["parent_document"]["id"], "vault-transit")

    @patch("app.documentation._configmap")
    def test_unknown_parent_is_rejected(self, configmap):
        body = self.configmap()
        body["data"]["catalog.yaml"] += "    parent: missing\n"
        configmap.return_value = body
        with self.assertRaises(documentation.DocumentationError):
            documentation.catalog()


if __name__ == "__main__":
    unittest.main()
