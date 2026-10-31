import datetime as dt
import unittest

from app.lifecycle import lifecycle_history


class LifecycleHistoryTests(unittest.TestCase):
    def test_correlates_successful_expiry_deletion(self):
        audits = [
            {"action": "create", "profile": "lab", "owner": "alice", "job_id": "create1",
             "submitted_at": "2026-10-31T08:00:00+00:00", "completed_at": "2026-10-31T08:10:00+00:00",
             "status": "succeeded", "request": {"lifecycle": {"ttl": "1h"}}},
            {"action": "delete", "profile": "lab", "owner": "factory-expiry", "job_id": "delete1",
             "submitted_at": "2026-10-31T09:10:00+00:00", "completed_at": "2026-10-31T09:15:00+00:00",
             "status": "succeeded", "request": {"retain_data": False}},
        ]
        item = lifecycle_history(audits, dt.datetime(2026, 10, 31, 10, tzinfo=dt.timezone.utc))[0]
        self.assertEqual(item["state"], "Decommissioned on time")
        self.assertEqual(item["expires_at"], "2026-10-31T09:10:00+00:00")
        self.assertEqual(item["delete_job_id"], "delete1")

    def test_failed_build_is_not_reported_as_expired(self):
        audits = [{"action": "create", "profile": "lab", "owner": "alice", "job_id": "create1",
                   "submitted_at": "2026-10-31T08:00:00+00:00", "completed_at": "2026-10-31T08:20:00+00:00",
                   "status": "failed", "request": {"lifecycle": {"ttl": "1h"}}}]
        item = lifecycle_history(audits, dt.datetime(2026, 10, 31, 12, tzinfo=dt.timezone.utc))[0]
        self.assertEqual(item["state"], "Build failed")
        self.assertEqual(item["expires_at"], "")

    def test_overdue_success_without_delete_is_visible(self):
        audits = [{"action": "create", "profile": "dev", "owner": "bob", "job_id": "create2",
                   "submitted_at": "2026-10-31T08:00:00+00:00", "completed_at": "2026-10-31T08:05:00+00:00",
                   "status": "succeeded", "request": {"lifecycle": {"ttl": "1h"}}}]
        item = lifecycle_history(audits, dt.datetime(2026, 10, 31, 10, tzinfo=dt.timezone.utc))[0]
        self.assertEqual(item["state"], "Expiry overdue")


if __name__ == "__main__":
    unittest.main()
