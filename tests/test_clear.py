"""Clear results: removes one program's findings, leads, inventory and saved
responses; keeps the program, its settings, run history and request log."""
from unittest import mock

from fastapi.testclient import TestClient

from eeaao import db
from eeaao.app import app
from eeaao.bots import runner
from tests.test_headers import store
from tests.test_recon import PROGRAM, DbTestCase


def fill(pid):
    db.upsert_assets(pid, [("host", "www.example.com", {}), ("url", "https://www.example.com/", {})])
    store(pid, "https://www.example.com/", [("Content-Type", "text/html")], "<p>x</p>")
    for kind, type_ in (("finding", "missing_csp"), ("lead", "lead_xss_param")):
        db.upsert_finding(pid, {"kind": kind, "type": type_, "department": "x", "bot": "x",
                                "severity": "info", "title": "t", "target": "https://www.example.com/",
                                "detail": "", "evidence": {}, "key": type_})
    db.log_request(pid, None, "crawler", "target", "GET", "https://www.example.com/", 200, 5, 10, None)
    return db.create_run(pid, "recon", ["crawler"], {})


class ClearTests(DbTestCase):
    def setUp(self):
        super().setUp()
        self.client = TestClient(app, base_url="http://127.0.0.1")
        self.pid = db.create_program(PROGRAM)
        self.other = db.create_program(dict(PROGRAM, name="Other"))
        fill(self.pid)
        fill(self.other)

    def test_counts_then_clear(self):
        counts = self.client.get(f"/api/programs/{self.pid}/results").json()
        self.assertEqual(counts, {"findings": 1, "leads": 1, "inventory": 2, "responses": 1})

        answer = self.client.delete(f"/api/programs/{self.pid}/results")
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.json()["removed"], counts)

        after = self.client.get(f"/api/programs/{self.pid}/results").json()
        self.assertEqual(after, {"findings": 0, "leads": 0, "inventory": 0, "responses": 0})
        # kept: the program, its run history and its request log
        self.assertIsNotNone(db.get_program(self.pid))
        self.assertEqual(len(db.list_runs(self.pid)), 1)
        self.assertEqual(db.list_requests(self.pid, 10, 0)[0], 1)
        # the other program is untouched
        self.assertEqual(db.result_counts(self.other),
                         {"findings": 1, "leads": 1, "inventory": 2, "responses": 1})

    def test_refused_while_running(self):
        with mock.patch.object(runner, "active_run", return_value=99):
            answer = self.client.delete(f"/api/programs/{self.pid}/results")
            self.assertEqual(answer.status_code, 409)
            self.assertIn("in progress", answer.json()["detail"])
            self.assertEqual(self.client.delete(f"/api/programs/{self.pid}").status_code, 409)
        self.assertEqual(db.result_counts(self.pid)["findings"], 1)

    def test_unknown_program(self):
        self.assertEqual(self.client.delete("/api/programs/999/results").status_code, 404)
