import os
import sqlite3
import tempfile
import unittest
import app as application
from audit_db import initialize_database, read_recent_audit_events, write_audit_event

class PhaseTwoTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_directory.name, "test.db")
        application.app.config.update(TESTING=True, DATABASE=self.database_path)
        initialize_database(self.database_path)
        self.client = application.app.test_client()
    def tearDown(self): self.temp_directory.cleanup()
    def test_database_initializes(self):
        with sqlite3.connect(self.database_path) as connection:
            table = connection.execute("SELECT name FROM sqlite_master WHERE type=? AND name=?", ("table", "audit_log")).fetchone()
        self.assertEqual(table[0], "audit_log")
    def test_valid_event_can_be_stored(self):
        write_audit_event(self.database_path, user_id="DEMO-USER-001", action="PAGE_ENTER")
        self.assertEqual(read_recent_audit_events(self.database_path)[0]["action"], "PAGE_ENTER")
    def test_unsupported_action_is_rejected(self):
        self.assertEqual(self.client.post("/api/events", json={"action": "UNSAFE"}).status_code, 400)
        self.assertEqual(read_recent_audit_events(self.database_path), [])
    def test_member_directory_works(self): self.assertEqual(self.client.get("/").status_code, 200)
    def test_admin_dashboard_works(self): self.assertEqual(self.client.get("/admin").status_code, 200)

if __name__ == "__main__": unittest.main()
