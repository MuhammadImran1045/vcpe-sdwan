import argparse
import json
import os
import sys
from urllib.parse import urlparse

import requests

sys.path.insert(0, os.path.dirname(__file__))
from gns3_console import connect_console, run_command

DEFAULT_PROJECT_ID = "ca98b51a-b784-4af8-aaac-2f056ed44f6e"
EXPECTED_PROJECT = "sdwan-ci-image-lab"


def discover_image_lab(url, project_id, device):
    base = f"{url.rstrip('/')}/v2/projects/{project_id}"

    response = requests.get(base, timeout=10)
    response.raise_for_status()
    project = response.json()

    if (
        project.get("name") != EXPECTED_PROJECT
        or project.get("project_id") != project_id
        or project.get("status") != "opened"
    ):
        raise RuntimeError("Image-lab project safety check failed")

    response = requests.get(base + "/nodes", timeout=10)
    response.raise_for_status()

    matches = [
        node for node in response.json()
        if node.get("name") == device
    ]

    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one {device}")

    node = matches[0]

    if node.get("node_type") != "qemu":
        raise RuntimeError("Unexpected node type")

    if node.get("console_type") != "telnet":
        raise RuntimeError("Unexpected console type")

    if node.get("status") not in ("started", "running"):
        raise RuntimeError(f"{device} is not running")

    port = node.get("console")

    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise RuntimeError("Invalid console port")

    host = os.environ.get("GNS3_CONSOLE_HOST") or urlparse(url).hostname

    if not host:
        raise RuntimeError("Missing console host")

    return host, port


def get_api(session, endpoint):
    command = (
        "docker exec vcpe-forwarder "
        "curl -fsS --max-time 10 "
        f"http://127.0.0.1:9090{endpoint}"
    )

    output = run_command(session, command)
    start = output.find("{")

    if start < 0:
        raise RuntimeError(f"No JSON from {endpoint}")

    data, _ = json.JSONDecoder().raw_decode(output[start:])
    return data


def check(condition, description):
    if not condition:
        raise RuntimeError(f"FAIL: {description}")

    print(f"PASS: {description}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--gns3-url",
        default=os.environ.get("GNS3_URL")
    )
    parser.add_argument(
        "--project-id",
        default=DEFAULT_PROJECT_ID
    )
    parser.add_argument("--device", default="CPE-1")
    parser.add_argument("--lan-ip", default="10.0.1.1/24")
    parser.add_argument("--bridge", default="br-lan")
    parser.add_argument("--lan-member", default="eth2")
    parser.add_argument("--api-version", default="1.2.0")

    args = parser.parse_args()

    host, port = discover_image_lab(
        args.gns3_url,
        args.project_id,
        args.device
    )

    print(f"Project: {EXPECTED_PROJECT}")
    print(f"Device: {args.device}")
    print(f"Console: {host}:{port}")

    with connect_console(host, port) as session:
        health = get_api(session, "/api/v1/health")
        interfaces = get_api(session, "/api/v1/interfaces")
        bridges = get_api(session, "/api/v1/bridges")

    check(
        health.get("status") == "healthy",
        "Forwarder reports healthy"
    )

    check(
        health.get("version") == args.api_version,
        f"Forwarder API version {args.api_version}"
    )

    bridge = next(
        (
            item for item in interfaces.get("items", [])
            if item.get("name") == args.bridge
        ),
        None
    )

    check(
        bridge is not None and bridge.get("oper_state") == "up",
        f"{args.bridge} operational"
    )

    check(
        args.lan_ip in (bridge or {}).get("addresses", []),
        f"{args.bridge} address {args.lan_ip}"
    )

    check(
        any(
            item.get("bridge_id") == args.bridge
            and args.lan_member in item.get("members", [])
            for item in bridges.get("items", [])
        ),
        f"{args.lan_member} attached to {args.bridge}"
    )

    print("\nCI RESULT: PASS — Forwarder API validation")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nCI RESULT: FAIL — {exc}", file=sys.stderr)
        sys.exit(1)

