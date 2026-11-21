#!/usr/bin/env python3
"""Fast-track CI orchestrator for the EXISTING dedicated GNS3 sdwan-ci lab.

Modes:
  plan    - GET-only topology preflight; no changes or guest commands.
  verify  - topology preflight and read-only bidirectional namespace tests.
  repair  - explicitly authorized: open project, start stopped CPEs, restore
            known test underlay/routing and namespaces, then run connectivity tests.

This does NOT delete, reset, recreate QEMU disks, or create a fresh image.
Requires the tested gns3_live_compare.py, gns3_console.py, setup_namespace.sh
and ~/sdwan-ci/current-topology.json on the operator's computer.

The Telnet console is an unencrypted lab control channel; do not send secrets.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

import requests

PROJECT_NAME = "sdwan-ci"
EXPECTED_NODES = {
    "CPE-1": "qemu", "CPE-2": "qemu", "NAT1": "nat", "NAT2": "nat",
    "Switch1": "ethernet_switch", "Switch2": "ethernet_switch",
    "PC1": "vpcs", "PC2": "vpcs",
}
CPE = {
    "CPE-1": {"lan": "10.0.1.1/24", "remote": "10.0.2.0/24",
              "underlay": "10.200.0.1/30", "peer": "10.200.0.2"},
    "CPE-2": {"lan": "10.0.2.1/24", "remote": "10.0.1.0/24",
              "underlay": "10.200.0.2/30", "peer": "10.200.0.1"},
}
SOURCE = Path(__file__).resolve().parent


class CIError(Exception):
    """An actionable CI preflight or execution failure."""


def settings():
    base = os.getenv("GNS3_URL", "").strip().rstrip("/")
    project_id = os.getenv("GNS3_PROJECT_ID", "").strip()
    parsed = urlsplit(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise CIError("Set GNS3_URL to the existing university GNS3 server URL")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", project_id):
        raise CIError("Set GNS3_PROJECT_ID to the exact sdwan-ci project UUID")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise CIError("Do not embed credentials or query strings in GNS3_URL")
    return base, project_id


def api_get(session, base, suffix):
    result = session.get(base + suffix, timeout=15)
    result.raise_for_status()
    return result.json()


def api_post(session, base, suffix):
    result = session.post(base + suffix, json={}, timeout=25)
    result.raise_for_status()
    return result.json()


def inspect_project(session, server, project_id):
    api = f"{server}/v2/projects/{project_id}"
    project = api_get(session, api, "")
    if project.get("name") != PROJECT_NAME or project.get("project_id") != project_id:
        raise CIError("Refusing operation: selected project is NOT the expected sdwan-ci project")
    nodes = api_get(session, api, "/nodes")
    links = api_get(session, api, "/links")
    names = [n.get("name") for n in nodes]
    if len(nodes) != 8 or len(set(names)) != 8 or set(names) != set(EXPECTED_NODES):
        raise CIError("Unexpected nodes: do not modify or repair this GNS3 project")
    for node in nodes:
        if node.get("node_type") != EXPECTED_NODES[node["name"]]:
            raise CIError(f"Unexpected type for {node['name']}")
    if len(links) != 7:
        raise CIError(f"Expected 7 links, found {len(links)}; no changes permitted")
    return api, project, {n["name"]: n for n in nodes}


def run_existing_script(script_name, args, *, timeout=180):
    script = SOURCE / script_name
    if not script.is_file():
        raise CIError(f"Required tested script missing: {script}")
    command = [sys.executable, str(script), *args]
    print(f"\n>>> {script_name} {' '.join(args)}", flush=True)
    try:
        proc = subprocess.run(command, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout,
                              cwd=str(SOURCE), check=False)
    except subprocess.TimeoutExpired as exc:
        raise CIError(f"{script_name} timed out after {timeout} seconds") from exc
    output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    print(output[-9000:] if output else "(no output)", flush=True)
    if proc.returncode != 0:
        raise CIError(f"{script_name} {' '.join(args)} failed with exit code {proc.returncode}")
    return output


def load_console():
    script = SOURCE / "gns3_console.py"
    if not script.is_file():
        raise CIError("gns3_console.py is missing beside ci_fast_runner.py")
    spec = importlib.util.spec_from_file_location("gns3_ci_console", script)
    if spec is None or spec.loader is None:
        raise CIError("Cannot load gns3_console.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    required = ("discover", "connect_console", "run_command")
    for name in required:
        if not callable(getattr(module, name, None)):
            raise CIError(f"gns3_console.py lacks required tested function {name}")
    return module


def require_cpe_hardware(nodes):
    expected = {"hda_disk_image": "alpine-virt-3.18.4.qcow2",
                "hdb_disk_image": "empty20G.qcow2",
                "linked_clone": True, "ram": 2048, "cpus": 2, "adapters": 3}
    for name in CPE:
        node = nodes[name]
        prop = node.get("properties") or {}
        for key, value in expected.items():
            if prop.get(key) != value:
                raise CIError(f"{name} {key} changed; refusing CPE repair")


def ensure_started(session, api, nodes, console, wait_seconds=100):
    for name, node in nodes.items():
        if name not in CPE:
            continue
        status = node.get("status")
        if status in ("started", "running"):
            print(f"PASS: {name} already started")
            continue
        if status != "stopped":
            raise CIError(f"Refusing to start {name}: unexpected state {status!r}")
        print(f"START: {name} (existing QEMU disk preserved)", flush=True)
        api_post(session, api, f"/nodes/{node['node_id']}/start")

    for name in CPE:
        deadline = time.monotonic() + wait_seconds
        last_error = "no Linux shell response"
        while time.monotonic() < deadline:
            try:
                host, port = console.discover(name)
                with console.connect_console(host, port) as terminal:
                    result = console.run_command(terminal, "uname -s", timeout=10)
                    if "Linux" in result.splitlines():
                        print(f"PASS: {name} Linux shell ready")
                        break
                    last_error = f"Unexpected uname response: {result!r}"
            except (RuntimeError, requests.RequestException, OSError) as exc:
                last_error = str(exc)
            time.sleep(3)
        else:
            raise CIError(f"{name} did not become ready: {last_error}")


def repair_underlay(console):
    """Idempotently configure only eth1 + remote-LAN test route on known CPEs."""
    for name, cfg in CPE.items():
        print(f"\n--- Check/repair {name} test underlay ---", flush=True)
        host, port = console.discover(name)
        with console.connect_console(host, port) as terminal:
            bridge = console.run_command(terminal, "ip -4 -o addr show dev br-lan")
            found_bridge = re.findall(r"\binet\s+([0-9.]+/[0-9]+)\b", bridge)
            if cfg["lan"] not in found_bridge:
                raise CIError(f"{name} expected br-lan {cfg['lan']} is missing; stopping")
            if len(found_bridge) != 1:
                raise CIError(f"{name} has an unexpected additional br-lan address")
            print("PASS: expected br-lan IP present")

            output = console.run_command(terminal, "ip -4 -o addr show dev eth1")
            addr = re.findall(r"\binet\s+([0-9.]+/[0-9]+)\b", output)
            if any(value != cfg["underlay"] for value in addr):
                raise CIError(f"{name} eth1 has unexpected IPv4 address(es) {addr}; not overwriting")
            if cfg["underlay"] not in addr:
                console.run_command(terminal, "ip link set dev eth1 up")
                console.run_command(terminal, f"ip -4 addr add {cfg['underlay']} dev eth1")
                print(f"CONFIGURED: eth1 {cfg['underlay']}")
            else:
                console.run_command(terminal, "ip link set dev eth1 up")
                print(f"PASS: eth1 address {cfg['underlay']} already present")

            forwarding = console.run_command(terminal, "sysctl -n net.ipv4.ip_forward")
            if forwarding.strip() != "1":
                console.run_command(terminal, "sysctl -w net.ipv4.ip_forward=1")
                print("CONFIGURED: IPv4 forwarding enabled")
            else:
                print("PASS: IPv4 forwarding already enabled")

            route = console.run_command(terminal, f"ip -4 route show {cfg['remote']}")
            if route.strip():
                expected = (rf"^{re.escape(cfg['remote'])}\s+via\s+"
                            rf"{re.escape(cfg['peer'])}\s+dev\s+eth1(?:\s|$)")
                if not re.search(expected, route, flags=re.MULTILINE):
                    raise CIError(f"{name} has conflicting route to {cfg['remote']}: {route}")
                print(f"PASS: route to {cfg['remote']} already present")
            else:
                console.run_command(
                    terminal,
                    f"ip -4 route replace {cfg['remote']} via {cfg['peer']} dev eth1",
                )
                print(f"CONFIGURED: route to {cfg['remote']} via {cfg['peer']}")


def local_git_head():
    try:
        proc = subprocess.run(["git", "-C", str(SOURCE.parent.parent), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=5, check=False)
        return proc.stdout.strip() if proc.returncode == 0 else "unavailable"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def write_report(directory, mode, checks, success, error=None):
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    stem = now.strftime("ci_%Y%m%d_%H%M%S_%f")
    report = {"created_utc": now.isoformat(), "mode": mode, "result": "PASS" if success else "FAIL",
              "source_commit": local_git_head(),
              "scope": "existing sdwan-ci only; no clean rebuild or SD-WAN tunnel test",
              "checks": checks}
    if error:
        report["failure"] = str(error)
    json_path = directory / f"{stem}.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    suite = ET.Element("testsuite", {"name": "sdwan-fast-track", "tests": str(len(checks)),
                                     "failures": str(sum(c["status"] == "FAIL" for c in checks)),
                                     "errors": "0"})
    for check in checks:
        case = ET.SubElement(suite, "testcase", {"classname": "sdwan.ci", "name": check["name"]})
        if check["status"] == "FAIL":
            ET.SubElement(case, "failure", {"message": check.get("detail", "Failed")}).text = check.get("detail", "Failed")
        elif check["status"] == "SKIP":
            ET.SubElement(case, "skipped", {"message": check.get("detail", "Skipped")})
    xml_path = directory / f"{stem}.xml"
    ET.ElementTree(suite).write(xml_path, encoding="utf-8", xml_declaration=True)
    print(f"\nSaved JSON report: {json_path}")
    print(f"Saved JUnit XML : {xml_path}")


def run(args):
    checks = []
    def check(name, function):
        print(f"\n=== {name} ===", flush=True)
        try:
            result = function()
            checks.append({"name": name, "status": "PASS", "detail": "Completed"})
            return result
        except Exception as exc:  # always record a failure before stopping
            checks.append({"name": name, "status": "FAIL", "detail": str(exc)})
            raise

    try:
        server, project_id = settings()
        with requests.Session() as session:
            api, project, nodes = check("Dedicated-project safety check", lambda: inspect_project(session, server, project_id))
            check("CPE VM hardware safety check", lambda: require_cpe_hardware(nodes))
            check("Saved-versus-live topology comparison", lambda: run_existing_script("gns3_live_compare.py", [], timeout=50))

            if args.mode == "plan":
                print("\nPLAN ONLY: no CPE changes, no guest commands, no project reset")
            elif args.mode == "verify":
                check("Bidirectional routed namespace tests", lambda: run_existing_script("gns3_console.py", ["--test-cross"], timeout=180))
            elif args.mode == "repair":
                if not args.allow_cpe_changes:
                    raise CIError("Repair requires explicit --allow-cpe-changes; nothing was changed")
                console = check("Load tested console client", load_console)
                if project.get("status") == "closed":
                    check("Open only the dedicated CI project", lambda: api_post(session, api, "/open"))
                elif project.get("status") != "opened":
                    raise CIError(f"Unexpected project state: {project.get('status')}")
                check("Start/wait for existing two CPEs", lambda: ensure_started(session, api, nodes, console))
                check("Recover eth1 test underlay and LAN routes", lambda: repair_underlay(console))
                check("Recover/verify namespaces and DHCP", lambda: run_existing_script("gns3_console.py", ["--recover-both"], timeout=210))
                check("Bidirectional routed namespace tests", lambda: run_existing_script("gns3_console.py", ["--test-cross"], timeout=210))
            else:
                raise CIError(f"Unexpected mode {args.mode}")
    except (CIError, requests.RequestException, RuntimeError, OSError, ValueError) as exc:
        if not checks or checks[-1]["status"] != "FAIL":
            checks.append({"name": "Pipeline preflight/execution", "status": "FAIL", "detail": str(exc)})
        print(f"\nCI RESULT: FAIL — {exc}", file=sys.stderr)
        write_report(args.report_dir, args.mode, checks, False, exc)
        return 1
    print("\nCI RESULT: PASS")
    write_report(args.report_dir, args.mode, checks, True)
    return 0


def main():
    parser = argparse.ArgumentParser(description="SD-WAN CI fast-track orchestrator (does not delete/rebuild disks)")
    parser.add_argument("--mode", choices=("plan", "verify", "repair"), default="plan")
    parser.add_argument("--allow-cpe-changes", action="store_true", help="Required for mode=repair; changes CPE eth1, routes, namespaces")
    parser.add_argument("--report-dir", type=Path, default=SOURCE / "test-results")
    args = parser.parse_args()
    if args.mode != "repair" and args.allow_cpe_changes:
        parser.error("--allow-cpe-changes is only for --mode repair")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
