import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import app as application
from audit_db import initialize_database, read_recent_audit_events


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_directory.name, "test.db")
        application.app.config.update(TESTING=True, DATABASE=self.database_path)
        initialize_database(self.database_path)
        application._rate_limit_state.clear()
        self.client = application.app.test_client()

    def tearDown(self):
        application._rate_limit_state.clear()
        self.temp_directory.cleanup()

    def add_events(self, action, count, seconds_apart=120):
        now = datetime.now(timezone.utc)
        rows = []
        for index in range(count):
            profile_id = None
            if action == "PROFILE_VIEW":
                profile_id = application.MEMBERS[index % len(application.MEMBERS)]["member_id"]
            rows.append((application.DEMO_USER_ID, (now - timedelta(seconds=index * seconds_apart)).isoformat(),
                         action, profile_id))
        with sqlite3.connect(self.database_path) as connection:
            connection.executemany(
                "INSERT INTO audit_log (user_id, timestamp, action, profile_id) VALUES (?, ?, ?, ?)", rows)

    def test_low_user_can_download(self):
        response = self.client.get("/api/profiles/DEMO-1001/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(read_recent_audit_events(self.database_path)[0]["action"], "API_REQUEST")

    def test_medium_user_can_use_sensitive_action(self):
        self.add_events("API_REQUEST", 30)
        self.add_events("SEARCH", 15)
        self.add_events("PROFILE_VIEW", 6)
        self.add_events("COPY_ATTEMPT", 2)
        response = self.client.post("/api/events", json={"action": "COPY_ATTEMPT"})
        self.assertEqual(response.status_code, 201)

    def test_high_user_is_restricted_and_audited(self):
        self.add_events("PROFILE_VIEW", 50, 2)
        response = self.client.get("/api/profiles/DEMO-1001/download")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json["enforcement"], "ACTION_RESTRICTED")
        self.assertEqual(read_recent_audit_events(self.database_path)[0]["action"], "ACTION_RESTRICTED")

    def test_critical_user_is_blocked_and_audited(self):
        self.add_events("PROFILE_VIEW", 40, 2)
        self.add_events("COPY_ATTEMPT", 16, 2)
        self.add_events("DOWNLOAD", 16, 2)
        self.add_events("API_REQUEST", 100, 2)
        response = self.client.post("/api/events", json={"action": "COPY_ATTEMPT"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json["enforcement"], "ACTION_BLOCKED")

    def test_rate_limit_returns_429_and_is_audited(self):
        original_limit = application.RATE_LIMITS["COPY_ATTEMPT"]
        application.RATE_LIMITS["COPY_ATTEMPT"] = 2
        try:
            for _ in range(2):
                self.assertEqual(self.client.post("/api/events", json={"action": "COPY_ATTEMPT"}).status_code, 201)
            response = self.client.post("/api/events", json={"action": "COPY_ATTEMPT"})
        finally:
            application.RATE_LIMITS["COPY_ATTEMPT"] = original_limit
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json["enforcement"], "RATE_LIMITED")
        self.assertEqual(read_recent_audit_events(self.database_path)[0]["action"], "RATE_LIMITED")


if __name__ == "__main__":
    unittest.main()
