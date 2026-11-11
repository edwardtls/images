import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("OIDC_ISSUER", "https://kc.example.test/realms/d00s")
os.environ.setdefault("WORKER_IMAGE", "example.test/factory:test")
os.environ.setdefault("SESSION_SECRET", "test-only")

import psycopg

from app import device_egress_store
from app.main import app
from app.security import ADMIN_GROUP

BASE = "https://factory.apps.d00s.org"


def device(device_id, route, up, down):
    return {"id": device_id, "name": device_id.upper(), "route": route,
            "usage": {"total": {"up": up, "down": down},
                      "session": {"started_at": "2026-11-11 12:05", "up": up, "down": down} if route == "us" else None}}


class FakeConnection:
    """Answers the store's SELECTs from canned rows and records INSERTs."""

    def __init__(self, previous=None, last_route=None):
        self.previous, self.last_route, self.inserts = previous or {}, last_route or {}, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        result = MagicMock()
        if "SELECT total_up" in sql:
            result.fetchone.return_value = self.previous.get(params[0])
        elif "SELECT route" in sql:
            route = self.last_route.get(params[0])
            result.fetchone.return_value = (route,) if route else None
        elif sql.lstrip().startswith("INSERT"):
            self.inserts.append((sql, params))
        return result


class StoreTests(unittest.TestCase):
    def collect(self, devices, connection):
        with patch("app.device_egress_store.device_egress.status", return_value={"devices": devices}), \
                patch("app.device_egress_store.security_store._connect", return_value=connection):
            return device_egress_store.collect()

    def samples(self, connection):
        return [params for sql, params in connection.inserts if "device_egress_samples" in sql]

    def test_first_sample_stores_the_totals_and_an_observed_route(self):
        connection = FakeConnection()
        result = self.collect([device("apple-tv", "us", 100, 900), device("ps5", "atlantis", 0, 0)], connection)
        self.assertEqual(result, {"devices": 1})  # PS5 never used the US path
        sample = self.samples(connection)[0]
        self.assertEqual(sample[1], "apple-tv")
        self.assertEqual(sample[4:8], (100, 900, 100, 900))
        events = [params for sql, params in connection.inserts if "device_egress_events" in sql]
        self.assertEqual([event[1:4] for event in events], [("apple-tv", "APPLE-TV", "us")])

    def test_later_samples_store_the_growth_and_survive_a_reset(self):
        connection = FakeConnection(previous={"apple-tv": (100, 900), "ps5": (5000, 7000)},
                                    last_route={"apple-tv": "us", "ps5": "us"})
        self.collect([device("apple-tv", "us", 160, 2900), device("ps5", "us", 10, 20)], connection)
        by_device = {params[1]: params for params in self.samples(connection)}
        self.assertEqual(by_device["apple-tv"][6:8], (60, 2000))
        self.assertEqual(by_device["ps5"][6:8], (10, 20))  # counters restarted below the last total
        self.assertFalse([sql for sql, _ in connection.inserts if "device_egress_events" in sql])

    def test_switch_back_is_observed_once(self):
        connection = FakeConnection(previous={"apple-tv": (160, 2900)}, last_route={"apple-tv": "us"})
        self.collect([device("apple-tv", "atlantis", 160, 2900)], connection)
        self.assertEqual(self.samples(connection)[0][6:8], (0, 0))
        events = [params for sql, params in connection.inserts if "device_egress_events" in sql]
        self.assertEqual(events[0][3], "atlantis")


class SwitchAuditTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        with self.client.session_transaction(base_url=BASE) as session:
            session["user"] = {"sub": "admin-subject", "preferred_username": "edward", "groups": [ADMIN_GROUP]}
            session["csrf"] = "token"

    def test_switch_is_recorded_with_the_administrator(self):
        state = {"devices": [device("apple-tv", "us", 0, 0)]}
        with patch("app.main.device_egress.switch", return_value=state), \
                patch("app.main.device_egress_store.record_switch") as record:
            response = self.client.post("/routing/apple-tv", data={"csrf": "token", "route": "us"}, base_url=BASE)
        self.assertEqual(response.status_code, 303)
        recorded_device, route, actor = record.call_args.args
        self.assertEqual((recorded_device["id"], route, actor), ("apple-tv", "us", "edward"))

    def test_a_database_outage_does_not_undo_the_switch(self):
        with patch("app.main.device_egress.switch", return_value={"devices": []}), \
                patch("app.main.device_egress_store.record_switch", side_effect=psycopg.OperationalError("down")):
            response = self.client.post("/routing/apple-tv", data={"csrf": "token", "route": "atlantis"},
                                        base_url=BASE)
        self.assertEqual(response.status_code, 303)

    def test_history_is_shown(self):
        history = {"monthly": [{"month": "2026-11", "device_id": "apple-tv", "device_name": "Apple TV",
                                "up": 2000000, "down": 3000000000}],
                   "events": [{"at": "2026-11-11 12:05", "device_id": "apple-tv", "device_name": "Apple TV",
                               "route": "us", "actor": "edward"}]}
        status = {"devices": [], "path": {"ready": True, "gateway": "192.168.86.1"}}
        with patch("app.main.device_egress.status", return_value=status), \
                patch("app.main.device_egress_store.history", return_value=history):
            page = self.client.get("/routing", base_url=BASE).get_data(as_text=True)
        self.assertIn("US path by month", page)
        self.assertIn("3.0 GB", page)
        self.assertIn("2026-11-11 12:05", page)
        self.assertIn("edward", page)


if __name__ == "__main__":
    unittest.main()
