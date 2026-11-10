import datetime as dt
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

from app import ai_worker

NOW = dt.datetime(2026, 11, 10, 12, 0, tzinfo=dt.timezone.utc)


def cluster(namespace, name, archiving="True"):
    return {"metadata": {"namespace": namespace, "name": name},
            "status": {"conditions": [{"type": "ContinuousArchiving", "status": archiving, "message": "boom"}]}}


def backup(namespace, cluster_name, name, phase, created, stopped=None):
    status = {"phase": phase}
    if stopped:
        status["stoppedAt"] = stopped
    return {"metadata": {"namespace": namespace, "name": name, "creationTimestamp": created},
            "spec": {"cluster": {"name": cluster_name}}, "status": status}


class BackupActionTests(unittest.TestCase):
    def run_actions(self, clusters, backups):
        calls = []

        def api(method, path, payload=None, query=None):
            calls.append((method, path, payload))
            if method == "GET":
                return {"items": clusters if path.endswith("/clusters") else backups}
            return {}

        with patch("app.ai_worker.kube.api", side_effect=api):
            findings, actions = ai_worker._backup_actions(NOW)
        return findings, actions, [c for c in calls if c[0] != "GET"]

    def test_healthy_clusters_need_nothing(self):
        findings, actions, writes = self.run_actions(
            [cluster("redeem", "db")],
            [backup("redeem", "db", "b1", "completed", "2026-11-10T01:30:00Z", "2026-11-10T01:35:00Z")])
        self.assertEqual((findings, actions, writes), ([], [], []))

    def test_failed_latest_backup_is_retried_once(self):
        findings, actions, writes = self.run_actions(
            [cluster("redeem", "db")],
            [backup("redeem", "db", "b1", "completed", "2026-11-09T01:30:00Z", "2026-11-09T01:35:00Z"),
             backup("redeem", "db", "b2", "failed", "2026-11-10T01:30:00Z")])
        self.assertEqual([a["runbook"] for a in actions], ["retry-failed-backup"])
        method, path, body = writes[0]
        self.assertEqual((method, path), ("POST", "/apis/postgresql.cnpg.io/v1/namespaces/redeem/backups"))
        self.assertEqual(body["spec"], {"cluster": {"name": "db"}, "method": "plugin", "target": "prefer-standby",
                                        "pluginConfiguration": {"name": "barman-cloud.cloudnative-pg.io"}})
        self.assertTrue(any("failed" in f for f in findings))

    def test_no_retry_while_a_backup_runs(self):
        _, actions, writes = self.run_actions(
            [cluster("redeem", "db")],
            [backup("redeem", "db", "b1", "running", "2026-11-10T01:00:00Z"),
             backup("redeem", "db", "b2", "failed", "2026-11-10T01:30:00Z")])
        self.assertEqual((actions, writes), ([], []))

    def test_superseded_failures_are_removed_and_stale_backups_reported(self):
        findings, actions, writes = self.run_actions(
            [cluster("factory", "sec", archiving="False")],
            [backup("factory", "sec", "old", "failed", "2026-11-07T01:30:00Z"),
             backup("factory", "sec", "ok", "completed", "2026-11-08T01:30:00Z", "2026-11-08T01:31:00Z")])
        self.assertEqual(writes, [("DELETE", "/apis/postgresql.cnpg.io/v1/namespaces/factory/backups/old", None)])
        self.assertEqual([a["runbook"] for a in actions], ["cleanup-superseded-failure"])
        self.assertTrue(any("WAL archiving failing for factory/sec" in f for f in findings))
        self.assertTrue(any("in the last 30 hours" in f for f in findings))


if __name__ == "__main__":
    unittest.main()
