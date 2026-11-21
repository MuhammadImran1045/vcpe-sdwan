"""Offline tests for fast-track CI safety; no GNS3 connection is made."""

import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch, Mock

import ci_fast_runner as ci


class FakeResponse:
    def __init__(self, data):
        self.data = data
    def raise_for_status(self):
        pass
    def json(self):
        return self.data


class FakeSession:
    def __init__(self, *, bad=False):
        self.bad = bad
        self.posted = []
        self.nodes = [
            {"node_id": str(i), "name": name, "node_type": typ,
             "status": "started", "properties": {}}
            for i, (name, typ) in enumerate(ci.EXPECTED_NODES.items())
        ]
    def get(self, url, timeout):
        if url.endswith("/nodes"):
            return FakeResponse(self.nodes)
        if url.endswith("/links"):
            return FakeResponse([{}] * 7)
        if self.bad:
            return FakeResponse({"project_id": "wrong", "name": "Mohammad"})
        return FakeResponse({"project_id": "12345678-1234-1234-1234-123456789abc",
                             "name": "sdwan-ci", "status": "opened"})
    def post(self, url, json, timeout):
        self.posted.append(url)
        return FakeResponse({})


class FakeConsole:
    def discover(self, name):
        return ("local-test", 1000)
    class Session:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    def connect_console(self, host, port):
        return self.Session()
    def run_command(self, term, command):
        if command == "ip -4 -o addr show dev br-lan":
            return '1: br-lan inet 10.0.1.1/24 scope global br-lan'
        return ""


class CIUnitTests(unittest.TestCase):
    def setUp(self):
        self.project_id = "12345678-1234-1234-1234-123456789abc"
        self.envpatch = patch.dict("os.environ", {
            "GNS3_URL": "http://lab.example:3080", "GNS3_PROJECT_ID": self.project_id})
        self.envpatch.start()
        self.addCleanup(self.envpatch.stop)

    def test_project_accepted(self):
        session = FakeSession()
        api, project, nodes = ci.inspect_project(session, "http://lab.example:3080", self.project_id)
        self.assertEqual(project["name"], "sdwan-ci")
        self.assertEqual(len(nodes), 8)
        self.assertEqual(session.posted, [])

    def test_wrong_project_rejected_without_post(self):
        session = FakeSession(bad=True)
        with self.assertRaises(ci.CIError):
            ci.inspect_project(session, "http://lab.example:3080", self.project_id)
        self.assertEqual(session.posted, [])

    def test_plan_is_non_mutating(self):
        with tempfile.TemporaryDirectory() as folder:
            args = Mock(mode="plan", report_dir=Path(folder), allow_cpe_changes=False)
            with patch.object(ci, "inspect_project", return_value=("api", {"status": "opened"}, {})), \
                 patch.object(ci, "require_cpe_hardware"), \
                 patch.object(ci, "run_existing_script") as scripts:
                self.assertEqual(ci.run(args), 0)
                scripts.assert_called_once_with("gns3_live_compare.py", [], timeout=50)
            self.assertEqual(len(list(Path(folder).glob("*.json"))), 1)
            self.assertEqual(len(list(Path(folder).glob("*.xml"))), 1)

    def test_verify_runs_cross_only(self):
        with tempfile.TemporaryDirectory() as folder:
            args = Mock(mode="verify", report_dir=Path(folder), allow_cpe_changes=False)
            with patch.object(ci, "inspect_project", return_value=("api", {"status": "opened"}, {})), \
                 patch.object(ci, "require_cpe_hardware"), \
                 patch.object(ci, "run_existing_script") as scripts:
                self.assertEqual(ci.run(args), 0)
                self.assertEqual(scripts.call_count, 2)
                scripts.assert_any_call("gns3_console.py", ["--test-cross"], timeout=180)

    def test_repair_requires_explicit_ack(self):
        with tempfile.TemporaryDirectory() as folder:
            args = Mock(mode="repair", report_dir=Path(folder), allow_cpe_changes=False)
            with patch.object(ci, "inspect_project", return_value=("api", {"status": "opened"}, {})), \
                 patch.object(ci, "require_cpe_hardware"), \
                 patch.object(ci, "run_existing_script") as scripts:
                self.assertEqual(ci.run(args), 1)
                scripts.assert_called_once_with("gns3_live_compare.py", [], timeout=50)
            self.assertIn('"result": "FAIL"', next(Path(folder).glob("*.json")).read_text())

    def test_underlay_refuses_unexpected_lan(self):
        class Mismatch(FakeConsole):
            def run_command(self, term, command):
                if command == "ip -4 -o addr show dev br-lan":
                    return "1: br-lan inet 10.44.4.1/24"
                return ""
        with self.assertRaises(ci.CIError):
            ci.repair_underlay(Mismatch())


if __name__ == "__main__":
    unittest.main()
