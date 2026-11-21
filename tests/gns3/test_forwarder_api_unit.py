import importlib.util
import pathlib
import unittest
from unittest.mock import patch, Mock

MODULE_PATH = pathlib.Path(__file__).with_name("test_forwarder_api_live.py")

spec = importlib.util.spec_from_file_location("forwarder_ci", MODULE_PATH)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)

URL = "http://127.0.0.1:3080"
LAB_ID = "ca98b51a-b784-4af8-aaac-2f056ed44f6e"

def response(data):
    r = Mock()
    r.json.return_value = data
    r.raise_for_status.return_value = None
    return r

def project(name="sdwan-ci-image-lab"):
    return {
        "name": name,
        "project_id": LAB_ID,
        "status": "opened",
    }

def node(status="started"):
    return {
        "name": "CPE-1",
        "node_type": "qemu",
        "console_type": "telnet",
        "status": status,
        "console": 5000,
    }

class ForwarderSafetyTests(unittest.TestCase):

    @patch.object(ci.requests, "get")
    def test_correct_project(self, get):
        get.side_effect = [
            response(project()),
            response([node()])
        ]
        host, port = ci.discover_image_lab(URL, LAB_ID, "CPE-1")
        self.assertEqual((host, port), ("127.0.0.1", 5000))

    @patch.object(ci.requests, "get")
    def test_wrong_project_rejected(self, get):
        get.return_value = response(project("sdwan-ci"))
        with self.assertRaises(RuntimeError):
            ci.discover_image_lab(URL, LAB_ID, "CPE-1")
        self.assertEqual(get.call_count, 1)

    @patch.object(ci.requests, "get")
    def test_stopped_cpe_rejected(self, get):
        get.side_effect = [
            response(project()),
            response([node("stopped")])
        ]
        with self.assertRaises(RuntimeError):
            ci.discover_image_lab(URL, LAB_ID, "CPE-1")

    @patch.object(ci.requests, "get")
    def test_missing_cpe_rejected(self, get):
        get.side_effect = [
            response(project()),
            response([])
        ]
        with self.assertRaises(RuntimeError):
            ci.discover_image_lab(URL, LAB_ID, "CPE-1")

    @patch.object(ci.requests, "get")
    def test_invalid_console_rejected(self, get):
        bad = node()
        bad["console"] = 70000
        get.side_effect = [
            response(project()),
            response([bad])
        ]
        with self.assertRaises(RuntimeError):
            ci.discover_image_lab(URL, LAB_ID, "CPE-1")

    @patch.object(ci, "run_command")
    def test_forwarder_json_parsing(self, run):
        run.return_value = '{"status":"healthy","version":"1.2.0"}'
        result = ci.get_api(None, "/api/v1/health")
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["version"], "1.2.0")

    def test_failed_assertion_rejected(self):
        with self.assertRaises(RuntimeError):
            ci.check(False, "unhealthy Forwarder")

if __name__ == "__main__":
    unittest.main()
