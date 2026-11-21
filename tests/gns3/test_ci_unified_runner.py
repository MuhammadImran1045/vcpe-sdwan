import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch, Mock

PATH = pathlib.Path(__file__).with_name("ci_unified_runner.py")
spec = importlib.util.spec_from_file_location("unified_ci", PATH)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class UnifiedCITests(unittest.TestCase):

    @patch.object(ci.subprocess, "run")
    def test_successful_subprocess(self, run):
        run.return_value = Mock(
            returncode=0, stdout="CI RESULT: PASS", stderr=""
        )
        result = ci.run_test("Network CI", ["python", "test.py"], {})
        self.assertEqual(result["status"], "PASS")

    @patch.object(ci.subprocess, "run")
    def test_failed_subprocess(self, run):
        run.return_value = Mock(
            returncode=1, stdout="FAIL", stderr=""
        )
        result = ci.run_test("Network CI", ["python", "test.py"], {})
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["exit_code"], 1)

    @patch.object(ci.subprocess, "run")
    def test_timeout(self, run):
        run.side_effect = subprocess.TimeoutExpired("test", 5)
        result = ci.run_test("Network CI", ["python", "test.py"], {}, 5)
        self.assertEqual(result["status"], "FAIL")

    @patch.object(ci.subprocess, "run")
    def test_project_environment_isolation(self, run):
        run.return_value = Mock(
            returncode=0, stdout="PASS", stderr=""
        )

        with patch.dict(
            ci.os.environ,
            {"GNS3_URL": "http://127.0.0.1:3080"},
        ):
            with patch.object(ci, "save_reports", return_value=True):
                result = ci.main()

        self.assertEqual(result, 0)
        self.assertEqual(run.call_count, 2)

        network_env = run.call_args_list[0].kwargs["env"]
        forwarder_env = run.call_args_list[1].kwargs["env"]

        self.assertEqual(
            network_env["GNS3_PROJECT_ID"], ci.NETWORK_PROJECT
        )
        self.assertEqual(
            forwarder_env["GNS3_PROJECT_ID"], ci.IMAGE_LAB_PROJECT
        )

    def test_invalid_server_rejected(self):
        with patch.dict(ci.os.environ, {"GNS3_URL": ""}):
            self.assertEqual(ci.main(), 2)

    def test_json_and_junit_reports(self):
        checks = [
            {"name": "Network CI", "status": "PASS",
             "exit_code": 0, "detail": "OK"},
            {"name": "Forwarder CI", "status": "FAIL",
             "exit_code": 1, "detail": "Unavailable"},
        ]

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(ci, "REPORT_DIR", pathlib.Path(tmp)):
                result = ci.save_reports(
                    checks, "http://127.0.0.1:3080"
                )

            self.assertFalse(result)

            json_files = list(pathlib.Path(tmp).glob("*.json"))
            xml_files = list(pathlib.Path(tmp).glob("*.xml"))

            self.assertEqual(len(json_files), 1)
            self.assertEqual(len(xml_files), 1)

            report = json.loads(json_files[0].read_text())
            self.assertEqual(report["result"], "FAIL")

            suite = ET.parse(xml_files[0]).getroot()
            self.assertEqual(suite.attrib["failures"], "1")

    @patch.object(ci.subprocess, "run")
    def test_os_error(self, run):
        run.side_effect = OSError("Python executable unavailable")
        result = ci.run_test("Network CI", ["python"], {})
        self.assertEqual(result["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
