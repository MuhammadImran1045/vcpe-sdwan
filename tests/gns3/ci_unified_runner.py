"""Unified, read-only SD-WAN CI verification."""

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SOURCE = Path(__file__).resolve().parent
REPORT_DIR = SOURCE / "test-results"

NETWORK_PROJECT = "adc42d95-32bb-4b9f-857b-f9381205251a"
IMAGE_LAB_PROJECT = "ca98b51a-b784-4af8-aaac-2f056ed44f6e"


def run_test(name, command, env, timeout=240):
    print(f"\n=== {name} ===", flush=True)

    try:
        proc = subprocess.run(
            command,
            cwd=SOURCE,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )

        output = (proc.stdout or "") + (proc.stderr or "")
        print(output[-8000:] or "(no output)", flush=True)

        passed = proc.returncode == 0

        return {
            "name": name,
            "status": "PASS" if passed else "FAIL",
            "exit_code": proc.returncode,
            "detail": output[-8000:],
        }

    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"FAIL: {exc}", flush=True)

        return {
            "name": name,
            "status": "FAIL",
            "exit_code": None,
            "detail": str(exc),
        }


def save_reports(checks, server):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    stem = now.strftime("unified_ci_%Y%m%d_%H%M%S_%f")
    success = all(c["status"] == "PASS" for c in checks)

    report = {
        "created_utc": now.isoformat(),
        "mode": "verify-only",
        "result": "PASS" if success else "FAIL",
        "gns3_server": server,
        "network_project": NETWORK_PROJECT,
        "forwarder_project": IMAGE_LAB_PROJECT,
        "checks": checks,
    }

    json_path = REPORT_DIR / f"{stem}.json"
    json_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    suite = ET.Element("testsuite", {
        "name": "sdwan-unified-ci",
        "tests": str(len(checks)),
        "failures": str(sum(c["status"] == "FAIL" for c in checks)),
        "errors": "0",
    })

    for check in checks:
        case = ET.SubElement(suite, "testcase", {
            "classname": "sdwan.unified",
            "name": check["name"],
        })

        if check["status"] == "FAIL":
            failure = ET.SubElement(case, "failure", {
                "message": f"Exit code: {check['exit_code']}",
            })
            failure.text = check["detail"]

    xml_path = REPORT_DIR / f"{stem}.xml"
    ET.ElementTree(suite).write(
        xml_path,
        encoding="utf-8",
        xml_declaration=True,
    )

    print(f"\nJSON report : {json_path}")
    print(f"JUnit report: {xml_path}")

    return success


def main():
    server = os.environ.get("GNS3_URL", "").strip().rstrip("/")
    parsed = urlsplit(server)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        print("FAIL: Set a valid GNS3_URL without credentials")
        return 2

    print("=== UNIFIED SD-WAN CI VERIFICATION ===")
    print("Mode: READ ONLY")
    print("Network project: sdwan-ci")
    print("Forwarder project: sdwan-ci-image-lab")

    network_env = os.environ.copy()
    network_env["GNS3_URL"] = server
    network_env["GNS3_PROJECT_ID"] = NETWORK_PROJECT

    forwarder_env = os.environ.copy()
    forwarder_env["GNS3_URL"] = server
    forwarder_env["GNS3_PROJECT_ID"] = IMAGE_LAB_PROJECT

    checks = []

    checks.append(run_test(
        "Two-CPE network connectivity",
        [
            sys.executable,
            str(SOURCE / "ci_fast_runner.py"),
            "--mode", "verify",
        ],
        network_env,
    ))

    checks.append(run_test(
        "Forwarder API validation",
        [
            sys.executable,
            str(SOURCE / "test_forwarder_api_live.py"),
            "--gns3-url", server,
            "--project-id", IMAGE_LAB_PROJECT,
        ],
        forwarder_env,
    ))

    success = save_reports(checks, server)

    print("\n=== FINAL CI SUMMARY ===")
    for check in checks:
        print(f"{check['name']}: {check['status']}")

    print(f"\nCI RESULT: {'PASS' if success else 'FAIL'}")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
