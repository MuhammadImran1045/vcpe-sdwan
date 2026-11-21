#!/usr/bin/env python3
"""Detect what a GNS3 telnet console is currently showing.

Default mode is PASSIVE: the detector connects, listens and closes. It sends
no bytes at all, not even replies to telnet option negotiation, so it cannot
type into the console.

With --wake it may send exactly one carriage return ("\\r") after the passive
listen, so that an idle console reprints its prompt. The carriage return is
NOT sent when the passive output already shows a prompt, or when it shows a
password prompt (a carriage return there would submit an empty password).

Nothing else is ever sent: no commands, no credentials, no configuration.

The console is found either directly (--host/--port) or by a read-only GNS3
API lookup (--project/--node, GET requests only). Close other console clients
(for example MobaXterm) first; a second client can steal or mix output.

Exit codes: 0 = prompt detected, 1 = no prompt recognised, 2 = connection or
lookup error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request

IAC, SB, SE = 255, 250, 240
NEGOTIATION = {251, 252, 253, 254}  # WILL, WONT, DO, DONT

# (kind, pattern) checked against the last non-empty line, first match wins.
PROMPTS = [
    ("password", re.compile(r"password:\s*$", re.I)),
    ("login", re.compile(r"\blogin:\s*$", re.I)),
    ("root-shell", re.compile(r"#\s*$")),
    ("user-shell", re.compile(r"\$\s*$")),
    ("vpcs", re.compile(r"^\S+>\s*$")),
]
BOOTING = re.compile(r"(booting|starting|loading|grub|seabios|kernel|openrc|\* )", re.I)


def strip_telnet(data: bytes) -> bytes:
    """Remove telnet IAC command and sub-negotiation sequences from raw bytes."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != IAC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        cmd = data[i + 1]
        if cmd == IAC:  # escaped 0xFF data byte
            out.append(IAC)
            i += 2
        elif cmd in NEGOTIATION:
            i += 3
        elif cmd == SB:
            end = data.find(bytes([IAC, SE]), i + 2)
            i = n if end < 0 else end + 2
        else:
            i += 2
    return bytes(out)


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]")


def clean_text(data: bytes) -> str:
    text = strip_telnet(data).decode("utf-8", "replace")
    text = ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return "".join(ch for ch in text if ch == "\n" or ch == "\t" or ch >= " ")


def last_line(text: str) -> str:
    lines = [line for line in text.split("\n") if line.strip()]
    return lines[-1].rstrip() if lines else ""


def classify(text: str) -> str:
    """Return the prompt kind shown at the end of the console output."""
    line = last_line(text)
    if not line:
        return "silent"
    for kind, pattern in PROMPTS:
        if pattern.search(line):
            return kind
    if BOOTING.search(line):
        return "booting"
    return "unknown"


def is_prompt(kind: str) -> bool:
    return kind in {"password", "login", "root-shell", "user-shell", "vpcs"}


def listen(sock: socket.socket, seconds: float) -> bytes:
    """Read whatever arrives for `seconds`; never writes to the socket."""
    data = bytearray()
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return bytes(data)
        sock.settimeout(min(remaining, 0.5))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:  # server closed the connection
            return bytes(data)
        data.extend(chunk)


def lookup_console(gns3_url: str, project: str, node: str) -> tuple[str, int]:
    """Find a node's console host/port with GET requests only."""
    def get(path: str):
        with urllib.request.urlopen(gns3_url.rstrip("/") + path, timeout=15) as response:
            return json.load(response)

    matches = [p for p in get("/v2/projects") if p.get("name") == project]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one project named {project!r}, found {len(matches)}")
    if matches[0].get("status") != "opened":
        raise RuntimeError(f"project {project!r} is {matches[0].get('status')}; open it first (this tool will not)")
    nodes = [n for n in get(f"/v2/projects/{matches[0]['project_id']}/nodes") if n.get("name") == node]
    if len(nodes) != 1:
        raise RuntimeError(f"expected exactly one node named {node!r} in {project!r}, found {len(nodes)}")
    n = nodes[0]
    if n.get("status") != "started":
        raise RuntimeError(f"node {node!r} is {n.get('status')}; it must be started")
    if n.get("console_type") != "telnet" or not n.get("console"):
        raise RuntimeError(f"node {node!r} has no telnet console ({n.get('console_type')})")
    host = n.get("console_host") or ""
    if host in ("", "0.0.0.0", "::"):
        host = urllib.parse.urlparse(gns3_url).hostname or ""
    return host, int(n["console"])


def detect(host: str, port: int, listen_seconds: float, wake: bool, wake_seconds: float) -> dict:
    result = {"host": host, "port": port, "mode": "wake" if wake else "passive",
              "bytes_sent": 0, "woke": False}
    with socket.create_connection((host, port), timeout=10) as sock:
        raw = listen(sock, listen_seconds)
        text = clean_text(raw)
        kind = classify(text)
        result["passive_kind"] = kind
        if wake and kind == "password":
            result["wake_skipped"] = "password prompt shown; a carriage return would submit an empty password"
        elif wake and is_prompt(kind):
            result["wake_skipped"] = "prompt already visible"
        elif wake:
            sock.sendall(b"\r")
            result["bytes_sent"] = 1
            result["woke"] = True
            more = listen(sock, wake_seconds)
            raw += more
            text = clean_text(raw)
            kind = classify(text)
    result["kind"] = kind
    result["prompt_detected"] = is_prompt(kind)
    result["last_line"] = last_line(text)[-120:]
    result["bytes_received"] = len(raw)
    return result


def parse_args(argv=None) -> argparse.Namespace:
    env = os.environ.get
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", help="console host (with --port)")
    parser.add_argument("--port", type=int, help="console TCP port (with --host)")
    parser.add_argument("--gns3-url", default=env("GNS3_URL"), help="for --project/--node lookup (GET only)")
    parser.add_argument("--project", help="GNS3 project name for lookup, e.g. sdwan-ci-image-lab")
    parser.add_argument("--node", help="node name for lookup, e.g. CPE-1")
    parser.add_argument("--listen", type=float, default=5.0, help="passive listen time in seconds (default 5)")
    parser.add_argument("--wake", action="store_true",
                        help="allow ONE carriage return if no prompt was seen passively")
    parser.add_argument("--wake-listen", type=float, default=3.0, help="listen time after the carriage return")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    direct = args.host is not None or args.port is not None
    lookup = args.project is not None or args.node is not None
    if direct == lookup:
        parser.error("use either --host and --port, or --project and --node")
    if direct and (args.host is None or args.port is None):
        parser.error("--host and --port must be given together")
    if lookup and (args.project is None or args.node is None or not args.gns3_url):
        parser.error("--project, --node and --gns3-url (or GNS3_URL) are required for lookup")
    if args.listen <= 0 or args.wake_listen <= 0:
        parser.error("listen times must be positive")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if args.project:
            host, port = lookup_console(args.gns3_url, args.project, args.node)
        else:
            host, port = args.host, args.port
        result = detect(host, port, args.listen, args.wake, args.wake_listen)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"console {result['host']}:{result['port']}  mode={result['mode']}  "
              f"bytes sent={result['bytes_sent']}  received={result['bytes_received']}")
        print(f"passive view: {result['passive_kind']}")
        if "wake_skipped" in result:
            print(f"wake skipped: {result['wake_skipped']}")
        print(f"result: {result['kind']}  prompt detected: {result['prompt_detected']}")
        print(f"last line: {result['last_line']!r}")
    return 0 if result["prompt_detected"] else 1


if __name__ == "__main__":
    sys.exit(main())
