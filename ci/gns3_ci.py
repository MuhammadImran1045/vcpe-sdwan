#!/usr/bin/env python3
"""GNS3 CI test for the vCPE SD-WAN project.

Every run replaces the dedicated CI project on the GNS3 server with the code
of the local checkout:

    NAT1 -- eth0 [CPE-1] eth2 -- Switch1 -- PC1      LAN 10.0.1.0/24 + netns ci-lan1
                    || wg0 (WireGuard over the WAN)
    NAT2 -- eth0 [CPE-2] eth2 -- Switch2 -- PC2      LAN 10.0.2.0/24 + netns ci-lan2

  1. Replace the dedicated GNS3 test project (REST API)
  2. Provision each CPE through its serial console: Docker + the Forwarder
     built from the local checkout (uploaded through the console, no Git needed)
  3. Configure each SD-WAN LAN (bridge, gateway address, DHCP server) through
     the Forwarder transaction API
  4. LAN connectivity per CPE: the wired PC and a virtual LAN client (network
     namespace) get leases from the same DHCP server and ping each other
  5. Inter-CPE connectivity: WireGuard tunnel between the CPEs, then
     PC/namespace on one site ping PC/namespace on the other site
  6. Reboot CPE-1 and verify LAN recovery, then inter-CPE connectivity again

Only the Python standard library is used. Example:

    GNS3_URL=http://<gns3-server>:3080 python ci/gns3_ci.py --project-name <disposable-project>

Exit code 0 = all checks passed, 1 = a check failed, 2 = infrastructure error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import socket
import sys
import tarfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

REPO_ROOT = Path(__file__).resolve().parent.parent
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>]")

TUNNEL = "wg0"
TUNNEL_PORT = 51820
KEY_DIR_HOST = "/data/vcpe/shared-keys"             # mounted read-only into the Forwarder
KEY_DIR_FORWARDER = "/var/lib/sdwan-cpe/keys"


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


class CheckFailed(Exception):
    """A test assertion failed."""


class InfraError(Exception):
    """The lab could not be built or driven (not a product failure)."""


# =====================================================================================
# GNS3 REST API
# =====================================================================================
class Gns3:
    def __init__(self, base_url: str, user: str | None = None, password: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json"}
        if user:
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"

    def request(self, method: str, path: str, body: dict | None = None, timeout: float = 120):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}/v2{path}", data=data, method=method, headers=self.headers
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise InfraError(f"GNS3 {method} {path} -> HTTP {exc.code}: {detail[:500]}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise InfraError(f"GNS3 {method} {path} failed: {exc}") from exc
        return json.loads(raw) if raw.strip() else None

    def version(self) -> str:
        return self.request("GET", "/version")["version"]

    def projects(self) -> list[dict]:
        return self.request("GET", "/projects")

    def create_project(self, name: str) -> dict:
        return self.request("POST", "/projects", {"name": name})

    def stop_all(self, project_id: str) -> None:
        self.request("POST", f"/projects/{project_id}/nodes/stop", {}, timeout=180)

    def close_project(self, project_id: str) -> None:
        self.request("POST", f"/projects/{project_id}/close", {}, timeout=180)

    def delete_project(self, project_id: str) -> None:
        try:
            self.stop_all(project_id)
        except InfraError:
            pass                                             # closed projects have no running nodes
        self.request("DELETE", f"/projects/{project_id}", timeout=180)

    def create_node(self, project_id: str, name: str, node_type: str, x: int, y: int,
                    properties: dict | None = None, **extra) -> dict:
        body = {"name": name, "node_type": node_type, "compute_id": "local", "x": x, "y": y}
        if properties:
            body["properties"] = properties
        body.update(extra)
        return self.request("POST", f"/projects/{project_id}/nodes", body)

    def link(self, project_id: str, a: dict, a_adapter: int, a_port: int,
             b: dict, b_adapter: int, b_port: int) -> dict:
        body = {"nodes": [
            {"node_id": a["node_id"], "adapter_number": a_adapter, "port_number": a_port},
            {"node_id": b["node_id"], "adapter_number": b_adapter, "port_number": b_port},
        ]}
        return self.request("POST", f"/projects/{project_id}/links", body)

    def start_all(self, project_id: str) -> None:
        self.request("POST", f"/projects/{project_id}/nodes/start", {}, timeout=300)

    def node(self, project_id: str, node_id: str) -> dict:
        return self.request("GET", f"/projects/{project_id}/nodes/{node_id}")


# =====================================================================================
# Telnet consoles
# =====================================================================================
class Console:
    """Minimal telnet client for a GNS3 node console."""

    def __init__(self, host: str, port: int, name: str, transcript_dir: Path) -> None:
        self.host = host
        self.port = port
        self.name = name
        self.sock: socket.socket | None = None
        self.buf = ""
        self._pending = b""
        transcript_dir.mkdir(parents=True, exist_ok=True)
        self.transcript = open(transcript_dir / f"console-{name}.log", "w", encoding="utf-8", errors="replace")

    def connect(self, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                self.sock = socket.create_connection((self.host, self.port), timeout=10)
                self.sock.settimeout(0.5)
                return
            except OSError as exc:
                last_error = exc
                time.sleep(2)
        raise InfraError(f"cannot connect to console {self.name} at {self.host}:{self.port}: {last_error}")

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self.transcript.close()

    def _strip_telnet(self, data: bytes) -> bytes:
        data = self._pending + data
        out = bytearray()
        i, n = 0, len(data)
        while i < n:
            byte = data[i]
            if byte != 255:
                out.append(byte)
                i += 1
                continue
            if i + 1 >= n:
                break
            command = data[i + 1]
            if command == 255:
                out.append(255)
                i += 2
            elif command in (251, 252, 253, 254):          # WILL / WONT / DO / DONT <option>
                if i + 2 >= n:
                    break
                i += 3
            elif command == 250:                           # subnegotiation ... IAC SE
                end = data.find(b"\xff\xf0", i + 2)
                if end < 0:
                    break
                i = end + 2
            else:
                i += 2
        self._pending = bytes(data[i:])
        return bytes(out)

    def pump(self) -> bool:
        """Read whatever is available. Returns True if new data arrived."""
        assert self.sock is not None
        try:
            data = self.sock.recv(65536)
        except socket.timeout:
            return False
        except OSError as exc:
            raise InfraError(f"console {self.name} read failed: {exc}") from exc
        if not data:
            raise InfraError(f"console {self.name} closed by GNS3")
        text = self._strip_telnet(data).decode("utf-8", errors="replace")
        text = ANSI_RE.sub("", text).replace("\r", "")
        if text:
            self.transcript.write(text)
            self.transcript.flush()
            self.buf += text
        return bool(text)

    def send(self, text: str) -> None:
        assert self.sock is not None
        try:
            self.sock.sendall(text.encode("utf-8"))
        except OSError as exc:
            raise InfraError(f"console {self.name} write failed: {exc}") from exc

    def read_until(self, pattern: str, timeout: float) -> tuple[str, re.Match]:
        """Wait for a regex. Returns (text before the match, match) and consumes both."""
        regex = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while True:
            match = regex.search(self.buf)
            if match:
                before = self.buf[: match.start()]
                self.buf = self.buf[match.end():]
                return before, match
            if time.monotonic() > deadline:
                tail = self.buf[-600:]
                raise InfraError(f"console {self.name}: timeout after {timeout:.0f}s waiting for /{pattern}/; last output:\n{tail}")
            self.pump()

    def drain(self, quiet: float = 0.6) -> None:
        last = time.monotonic()
        while time.monotonic() - last < quiet:
            if self.pump():
                last = time.monotonic()
        self.buf = ""


class LinuxConsole(Console):
    """Root shell on a Linux VM serial console (Alpine: autologin as root).

    The interactive busybox shell has its own line editor (echo, 1024-char line
    limit, TAB completion), so only short command lines are typed into it.
    Anything longer is uploaded as a base64 file read directly by `base64 -d`
    from the tty and then executed with `sh <file>`.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._counter = 0

    def wait_for_shell(self, timeout: float = 300) -> None:
        deadline = time.monotonic() + timeout
        next_poke = 0.0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_poke:
                self.send("\n")
                next_poke = now + 4
            self.pump()
            tail = self.buf[-200:]
            if re.search(r"login: ?$", tail):
                self.buf = ""
                self.send("root\n")
                next_poke = time.monotonic() + 4
                continue
            if re.search(r"[#$] ?$", tail):
                # Confirm it really is a shell that executes commands.
                self.buf = ""
                self.send('echo "__SH""ELL_OK__"\n')
                try:
                    self.read_until(r"__SHELL_OK__\n", timeout=8)
                except InfraError:
                    continue
                self.send("stty cols 250 rows 50\n")
                self.drain()
                return
        raise InfraError(f"console {self.name}: no root shell within {timeout:.0f}s; last output:\n{self.buf[-400:]}")

    def _next_tag(self) -> str:
        self._counter += 1
        return f"{self._counter:04d}"

    def _run_line(self, line: str, timeout: float) -> tuple[int, str]:
        if "\n" in line or len(line) > 200:
            raise ValueError("command line too long for the interactive shell; use run()")
        tag = self._next_tag()
        self.buf = ""
        # The marker is split with "" so the echoed command line never matches it.
        self.send(f'echo "__B""EG_{tag}__"; {line}; echo "__E""ND_{tag}__:$?"\n')
        self.read_until(rf"__BEG_{tag}__\n", timeout=30)
        output, match = self.read_until(rf"__END_{tag}__:(\d+)\n", timeout=timeout)
        return int(match.group(1)), output

    def write_file(self, path: str, data: bytes) -> None:
        digest = hashlib.sha256(data).hexdigest()
        encoded = base64.encodebytes(data).decode("ascii")          # 76-char lines
        lines = encoded.splitlines(keepends=True)
        # The serial console has no flow control: pace the upload, verify, retry slower.
        for attempt, (chunk_lines, pause) in enumerate(((12, 0.04), (6, 0.06), (3, 0.1)), start=1):
            self.buf = ""
            # base64 reads the tty itself (canonical mode); Ctrl-D on an empty line ends input.
            self.send(f"stty -echo; base64 -d > {path}; stty echo\n")
            time.sleep(0.5)
            for index in range(0, len(lines), chunk_lines):
                self.send("".join(lines[index:index + chunk_lines]))
                time.sleep(pause)
            self.send("\x04")
            time.sleep(0.3)
            rc, output = self._run_line(f"sha256sum {path}", timeout=60)
            if rc == 0 and digest in output:
                return
            log(f"{self.name}: upload of {path} corrupted (attempt {attempt}), retrying slower")
            self.drain(1.0)
        raise InfraError(f"console {self.name}: could not upload {path} intact")

    def run_rc(self, command: str, timeout: float = 120) -> tuple[int, str]:
        """Run a shell command or multi-line script. Returns (exit code, stdout+stderr)."""
        if "\n" in command or len(command) > 150:
            tag = self._next_tag()
            path = f"/tmp/ci_{tag}.sh"
            self.write_file(path, command.encode("utf-8"))
            rc, output = self._run_line(f"sh {path} 2>&1", timeout=timeout)
        else:
            rc, output = self._run_line(f"{{ {command} ; }} 2>&1", timeout=timeout)
        return rc, output.strip("\n")

    def run(self, command: str, timeout: float = 120, check: bool = True) -> str:
        """Like run_rc() but raises on a non-zero exit code and returns only the output."""
        rc, output = self.run_rc(command, timeout=timeout)
        if check and rc != 0:
            raise InfraError(f"{self.name}: command failed (rc={rc}):\n{command.strip()[:400]}\n--- output ---\n{output[-1500:]}")
        return output


class VpcsConsole(Console):
    PROMPT = r"\n[\w.\-\[\]]+> ?$"

    def wait_ready(self, timeout: float = 90) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.send("\n")
            end = time.monotonic() + 2
            while time.monotonic() < end:
                self.pump()
            if re.search(self.PROMPT, self.buf):
                self.buf = ""
                return
        raise InfraError(f"VPCS {self.name}: no prompt within {timeout:.0f}s")

    def run(self, command: str, timeout: float = 60) -> str:
        self.drain(0.3)
        self.send(command + "\n")
        output, _ = self.read_until(self.PROMPT, timeout=timeout)
        # Drop the echoed command line.
        return output.split("\n", 1)[1].strip("\n") if "\n" in output else output


# =====================================================================================
# Test report
# =====================================================================================
class Report:
    def __init__(self) -> None:
        self.results: list[tuple[str, bool, str]] = []
        self._lock = threading.Lock()

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        detail = " ".join(detail.split())[:200]
        with self._lock:
            self.results.append((name, bool(passed), detail))
        log(f"{'PASS' if passed else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        return bool(passed)

    def require(self, name: str, passed: bool, detail: str = "") -> None:
        if not self.check(name, passed, detail):
            raise CheckFailed(name)

    @property
    def failed(self) -> int:
        return sum(1 for _, passed, _ in self.results if not passed)

    def write_junit(self, path: Path, error: str | None = None) -> None:
        cases = []
        for name, passed, detail in self.results:
            body = "" if passed else f"<failure message={quoteattr(detail or 'failed')}/>"
            cases.append(f'  <testcase classname="gns3.sdwan" name={quoteattr(name)}>{body}</testcase>')
        errors = 0
        if error:
            errors = 1
            cases.append(f'  <testcase classname="gns3.sdwan" name="infrastructure"><error message="infrastructure error">{escape(error)}</error></testcase>')
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="gns3-sdwan-ci" tests="{len(cases)}" failures="{self.failed}" errors="{errors}">\n'
            + "\n".join(cases) + "\n</testsuite>\n"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(xml, encoding="utf-8")

    def summary(self) -> str:
        lines = ["", "=" * 78, "RESULT SUMMARY", "=" * 78]
        for name, passed, detail in self.results:
            lines.append(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        lines.append("=" * 78)
        lines.append(f"{len(self.results) - self.failed} passed, {self.failed} failed")
        return "\n".join(lines)


# =====================================================================================
# CPE provisioning scripts (run on the Alpine CPE as root)
# =====================================================================================
def build_source_archive(paths: list[str]) -> bytes:
    """tar.gz of the checkout parts the CPE needs (what CI is testing)."""
    skip_dirs = {"__pycache__", ".git", "var", "node_modules", ".pytest_cache"}
    buffer = io.BytesIO()

    def add(tar: tarfile.TarFile, path: Path) -> None:
        relative = path.relative_to(REPO_ROOT).as_posix()
        if path.is_dir():
            if path.name in skip_dirs:
                return
            for child in sorted(path.iterdir()):
                add(tar, child)
            return
        if path.suffix in {".pyc", ".pyo"}:
            return
        info = tarfile.TarInfo(relative)
        data = path.read_bytes()
        info.size = len(data)
        info.mode = 0o755
        info.mtime = int(path.stat().st_mtime)
        tar.addfile(info, io.BytesIO(data))

    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name in paths:
            path = REPO_ROOT / name
            if not path.exists():
                raise InfraError(f"source path missing in checkout: {name}")
            add(tar, path)
    return buffer.getvalue()


PROVISION_BASE = r"""
set -e
# --- Internet on the WAN port (GNS3 NAT cloud) ---
cat > /etc/network/interfaces <<'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF
ip link set eth0 up
udhcpc -i eth0 -n -q -t 10 -T 2 >/tmp/udhcpc-eth0.log 2>&1 || { cat /tmp/udhcpc-eth0.log; echo "no DHCP lease on eth0 (WAN)"; exit 1; }
rc-update add networking boot >/dev/null 2>&1 || true

# --- Data disk for Docker and the checkout ---
DISK=/dev/vdb
[ -b "$DISK" ] || DISK=/dev/sdb
[ -b "$DISK" ] || { echo "no second disk found"; cat /proc/partitions; exit 1; }
sed -i 's|^#\(.*/community\)$|\1|' /etc/apk/repositories
apk update >/tmp/apk.log 2>&1 || { tail -20 /tmp/apk.log; exit 1; }
apk add e2fsprogs >>/tmp/apk.log 2>&1 || { tail -20 /tmp/apk.log; exit 1; }
mkfs.ext4 -q -F "$DISK"
mkdir -p /data
grep -q " /data " /etc/fstab || echo "$DISK /data ext4 defaults 0 2" >> /etc/fstab
mount /data
rc-update add localmount boot >/dev/null 2>&1 || true

# The Alpine system disk is tiny (~185 MB): too small for the Docker binaries.
# Overlay /usr onto the data disk so packages installed from now on land there.
mkdir -p /data/usr-upper /data/usr-work
grep -q "^overlay /usr " /etc/fstab || echo "overlay /usr overlay lowerdir=/usr,upperdir=/data/usr-upper,workdir=/data/usr-work 0 0" >> /etc/fstab
mount /usr
df -h / /data | sed 's/^/  /'
"""

PROVISION_DOCKER = r"""
set -e
# iproute2: busybox `ip` has no `netns` support, needed for virtual LAN clients.
apk add docker docker-cli-compose curl iproute2 >>/tmp/apk.log 2>&1 || { tail -30 /tmp/apk.log; df -h /; exit 1; }
for m in bridge veth nf_tables tun wireguard; do
    modprobe $m 2>/dev/null || echo "note: module $m not loadable"
    grep -qx $m /etc/modules 2>/dev/null || echo $m >> /etc/modules
done

# A CPE is a router. Enable forwarding BEFORE Docker starts: when Docker has to
# enable it itself, it also sets the iptables FORWARD policy to DROP, which
# would block LAN <-> tunnel traffic.
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/10-cpe-forwarding.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
rc-update add sysctl boot >/dev/null 2>&1 || true

mkdir -p /etc/docker /data/docker
echo '{"data-root":"/data/docker"}' > /etc/docker/daemon.json
rc-update add docker default >/dev/null
service docker start >/tmp/docker-start.log 2>&1 || { cat /tmp/docker-start.log; exit 1; }
i=0
until docker info >/dev/null 2>&1; do
    i=$((i+1))
    [ $i -gt 60 ] && { echo "docker daemon did not start"; tail -30 /var/log/docker.log 2>/dev/null; exit 1; }
    sleep 1
done
docker --version
docker compose version
"""

DEPLOY_FORWARDER = r"""
set -e
rm -rf /data/vcpe && mkdir -p /data/vcpe
tar -xzf /data/source.tar.gz -C /data/vcpe
cd /data/vcpe
printf 'INFLUX_TOKEN=ci-token\nCONTROLLER_IP=192.0.2.1\n' > .env
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.alpine.yml"
$COMPOSE build vcpe-forwarder >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }
$COMPOSE up -d --no-deps vcpe-forwarder >/tmp/up.log 2>&1 || { tail -40 /tmp/up.log; exit 1; }
i=0
until curl -fsS http://127.0.0.1:9090/api/v1/health >/tmp/health.json 2>/dev/null; do
    i=$((i+1))
    [ $i -gt 60 ] && { echo "forwarder API not healthy"; docker logs --tail 40 vcpe-forwarder 2>&1; exit 1; }
    sleep 1
done
cat /tmp/health.json
"""

WAIT_FORWARDER = r"""
i=0
until curl -fsS http://127.0.0.1:9090/api/v1/health >/dev/null 2>&1; do
    i=$((i+1))
    [ $i -gt 150 ] && { docker ps -a 2>&1 | tail -5; exit 1; }
    sleep 1
done
sleep 5
"""

TUNNEL_KEYS = rf"""
set -e
mkdir -p {KEY_DIR_HOST}
umask 077
[ -s {KEY_DIR_HOST}/{TUNNEL}.private ] || docker exec vcpe-forwarder wg genkey > {KEY_DIR_HOST}/{TUNNEL}.private
echo "PUBKEY=$(docker exec -i vcpe-forwarder wg pubkey < {KEY_DIR_HOST}/{TUNNEL}.private)"
echo "WAN_IP=$(ip -4 -o addr show dev eth0 scope global | awk '{{print $4}}' | cut -d/ -f1 | head -n1)"
"""


# =====================================================================================
# Lab
# =====================================================================================
@dataclass
class Site:
    """One SD-WAN site: a CPE, its LAN switch, a wired PC and a virtual LAN client."""
    index: int
    name: str = ""
    lan_network: str = ""          # "10.0.1"
    tunnel_ip: str = ""            # "10.255.0.1"
    netns: str = ""
    console: LinuxConsole | None = None
    pc: VpcsConsole | None = None
    nodes: dict = field(default_factory=dict)
    lan_transaction: dict = field(default_factory=dict)
    tunnel_transaction: dict = field(default_factory=dict)
    wan_ip: str | None = None
    public_key: str | None = None
    pc_ip: str | None = None
    ns_ip: str | None = None

    def __post_init__(self) -> None:
        self.name = f"CPE-{self.index}"
        self.netns = f"ci-lan{self.index}"
        self.tunnel_ip = f"10.255.0.{self.index}"

    @property
    def gateway(self) -> str:
        return f"{self.lan_network}.1"

    @property
    def lan_prefix(self) -> str:
        return f"{self.lan_network}.1/24"

    @property
    def lan_cidr(self) -> str:
        return f"{self.lan_network}.0/24"


class SdwanTest:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.gns3 = Gns3(args.gns3_url, args.gns3_user, args.gns3_password)
        self.console_host = args.console_host or re.sub(r"^https?://", "", args.gns3_url).split("/")[0].rsplit(":", 1)[0]
        self.artifacts = Path(args.artifacts)
        self.report = Report()
        self.project: dict | None = None
        base = args.lan_base.rstrip(".")                     # "10.0" -> sites 10.0.1.0/24, 10.0.2.0/24
        self.sites = [Site(index=i, lan_network=f"{base}.{i}") for i in (1, 2)]

    # ---------------------------------------------------------------------------------
    def parallel(self, func) -> None:
        """Run func(site) for all sites at once; re-raise the first failure."""
        errors: list[BaseException] = []

        def worker(site: Site) -> None:
            try:
                func(site)
            except BaseException as exc:                     # noqa: BLE001 - re-raised below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(site,), name=site.name) for site in self.sites]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for kind in (InfraError, CheckFailed):
            for error in errors:
                if isinstance(error, kind):
                    raise error
        if errors:
            raise errors[0]

    # ---------------------------------------------------------------------------------
    def build_topology(self) -> None:
        args = self.args
        log(f"GNS3 server {args.gns3_url} version {self.gns3.version()}")

        matches = [project for project in self.gns3.projects()
                   if project["name"] == args.project_name]
        if len(matches) > 1:
            raise InfraError(f"Multiple projects named {args.project_name!r}; resolve the ambiguous test project")
        if matches:
            existing = matches[0]
            log(f"replacing dedicated test project {existing['name']} ({existing['project_id']})")
            self.gns3.delete_project(existing["project_id"])

        self.project = self.gns3.create_project(args.project_name)
        pid = self.project["project_id"]
        log(f"created project {args.project_name} ({pid})")

        for site in self.sites:
            y = -150 if site.index == 1 else 150
            cpe = self.gns3.create_node(
                pid, site.name, "qemu", -50, y,
                properties={
                    "hda_disk_image": args.cpe_image,
                    "hda_disk_interface": "virtio",
                    "hdb_disk_image": args.data_disk_image,
                    "hdb_disk_interface": "virtio",
                    "ram": args.cpe_ram,
                    "cpus": args.cpe_cpus,
                    "adapters": 3,
                    "adapter_type": "virtio-net-pci",
                    "platform": "x86_64",
                    "qemu_path": args.qemu_path,
                    "linked_clone": True,
                },
                console_type="telnet",
                port_name_format="eth{0}",
            )
            nat = self.gns3.create_node(pid, f"NAT{site.index}", "nat", -300, y)
            switch = self.gns3.create_node(pid, f"Switch{site.index}", "ethernet_switch", 150, y + 10)
            pc = self.gns3.create_node(pid, f"PC{site.index}", "vpcs", 350, y)

            # eth0 = WAN (NAT), eth1 = spare second WAN, eth2 = LAN
            self.gns3.link(pid, cpe, 0, 0, nat, 0, 0)
            self.gns3.link(pid, cpe, 2, 0, switch, 0, 0)
            self.gns3.link(pid, pc, 0, 0, switch, 0, 1)
            site.nodes = {"cpe": cpe, "pc": pc}
            log(f"topology: NAT{site.index} -- eth0 [{site.name}] eth2 -- Switch{site.index} -- PC{site.index}   LAN {site.lan_cidr}")

        self.gns3.start_all(pid)
        states = []
        for site in self.sites:
            cpe = self.gns3.node(pid, site.nodes["cpe"]["node_id"])
            pc = self.gns3.node(pid, site.nodes["pc"]["node_id"])
            states.append(f"{site.name}={cpe['status']} PC{site.index}={pc['status']}")
            site.console = LinuxConsole(self.console_host, cpe["console"], site.name, self.artifacts)
            site.pc = VpcsConsole(self.console_host, pc["console"], f"PC{site.index}", self.artifacts)
        self.report.require("New GNS3 project created and nodes started",
                            all("=started" in state.split()[0] and state.endswith("=started") for state in states),
                            ", ".join(states))
        for site in self.sites:
            site.console.connect()
            site.pc.connect()

    # ---------------------------------------------------------------------------------
    def provision(self, site: Site) -> None:
        cpe = site.console
        assert cpe is not None
        cpe.wait_for_shell(timeout=self.args.boot_timeout)
        log(f"{site.name}: shell ready (" + cpe.run("uname -sr; cat /etc/alpine-release 2>/dev/null").replace("\n", ", Alpine ") + ")")

        cpe.run(PROVISION_BASE, timeout=300)
        log(f"{site.name}: internet + data disk ready, installing Docker")
        cpe.run(PROVISION_DOCKER, timeout=600)
        self.report.require(f"{site.name}: provisioned (internet, data disk, Docker)", True)

        log(f"{site.name}: uploading checkout through the console ({len(self.archive) // 1024} KiB)")
        cpe.write_file("/data/source.tar.gz", self.archive)
        log(f"{site.name}: building and starting the Forwarder")
        health = cpe.run(DEPLOY_FORWARDER, timeout=self.args.build_timeout)
        self.report.require(f"{site.name}: Forwarder built from checkout and healthy", '"healthy"' in health, health[-120:])

        self.configure_lan(site)

    def apply_transaction(self, site: Site, transaction: dict, path: str) -> tuple[bool, str]:
        cpe = site.console
        assert cpe is not None
        cpe.write_file(path, json.dumps(transaction, indent=1).encode())
        raw = cpe.run(
            f"curl -sS -X POST -H 'Content-Type: application/json' --data @{path} "
            "http://127.0.0.1:9090/api/v1/transactions",
            timeout=180, check=False,
        )
        try:
            body = json.loads(raw[raw.index("{"):])
        except (ValueError, json.JSONDecodeError):
            return False, raw[-300:]
        if body.get("status") == "applied":
            return True, f"revision {body.get('revision')}"
        return False, raw[-300:]

    def configure_lan(self, site: Site) -> None:
        bridge = self.args.bridge
        # Same operations the Agent generates for a bridged lan-link with DHCP.
        site.lan_transaction = {
            "validate_only": False,
            "operations": [
                {"method": "PUT", "path": f"/api/v1/bridges/{bridge}", "payload": {"bridge_id": bridge, "admin_state": "up"}},
                {"method": "PUT", "path": f"/api/v1/bridges/{bridge}/members", "payload": {"interfaces": ["eth2"]}},
                {"method": "PUT", "path": "/api/v1/interfaces/eth2/state", "payload": {"state": "up"}},
                {"method": "PUT", "path": f"/api/v1/interfaces/{bridge}/addresses", "payload": {"addresses": [site.lan_prefix]}},
                {"method": "PUT", "path": f"/api/v1/services/dhcp/{bridge}", "payload": {
                    "enabled": True,
                    "served_interface": bridge,
                    "range_start": f"{site.lan_network}.100",
                    "range_end": f"{site.lan_network}.200",
                    "gateway": site.gateway,
                    "dns_servers": ["8.8.8.8"],
                    "lease_time": "3600s",
                }},
            ],
        }
        applied, detail = self.apply_transaction(site, site.lan_transaction, "/tmp/lan-transaction.json")
        self.report.require(f"{site.name}: LAN configured through Forwarder transaction API", applied, detail)
        self.verify_cpe_lan(site, "")

    def verify_cpe_lan(self, site: Site, when: str) -> None:
        cpe = site.console
        assert cpe is not None
        bridge = self.args.bridge
        suffix = f" {when}" if when else ""
        addresses = cpe.run(f"ip -4 -o addr show dev {bridge} 2>&1 || true")
        self.report.check(f"{site.name}: LAN bridge has gateway address{suffix}",
                          f" {site.lan_prefix} " in addresses + " ", addresses or "bridge missing")
        master = cpe.run("basename $(readlink /sys/class/net/eth2/master 2>/dev/null) 2>/dev/null || echo none")
        self.report.check(f"{site.name}: LAN port eth2 attached to bridge{suffix}", master.strip() == bridge, f"master={master.strip()}")
        rc, dnsmasq = cpe.run_rc(f"pgrep -af 'dnsmasq.*{bridge}'")
        self.report.check(f"{site.name}: DHCP server (dnsmasq) running{suffix}", rc == 0, dnsmasq[:120] or "not running")

    # ---------------------------------------------------------------------------------
    def ns_ping(self, site: Site, target: str | None, label: str, count: int = 3) -> None:
        if not target or not site.ns_ip:
            self.report.check(label, False, "no address")
            return
        rc, output = site.console.run_rc(f"ip netns exec {site.netns} ping -c {count} -W 2 {target}", timeout=60)
        loss = re.search(r"(\d+)% packet loss", output)
        self.report.check(label, rc == 0 and loss is not None and loss.group(1) == "0",
                          f"{site.ns_ip} -> {target}: {loss.group(0) if loss else output[-80:]}")

    def pc_ping(self, site: Site, target: str | None, label: str, count: int = 3) -> None:
        if not target or not site.pc_ip:
            self.report.check(label, False, "no address")
            return
        output = site.pc.run(f"ping {target} -c {count}", timeout=60)
        replies = len(re.findall(rf"bytes from {re.escape(target)}", output))
        self.report.check(label, replies == count, f"{site.pc_ip} -> {target}: {replies}/{count} replies")

    def test_lan(self, site: Site, when: str = "") -> None:
        cpe, pc = site.console, site.pc
        assert cpe is not None and pc is not None
        suffix = f" {when}" if when else ""
        network = re.escape(site.lan_network)
        name = site.name

        # Wired LAN host
        site.pc_ip = None
        dhcp_output = ""
        for _ in range(3):
            dhcp_output = pc.run("ip dhcp", timeout=60)
            match = re.search(rf"IP ({network}\.\d+)/(\d+) GW (\S+)", dhcp_output)
            if match:
                site.pc_ip = match.group(1)
                self.report.check(f"{name}: wired PC got DHCP lease{suffix}",
                                  match.group(3) == site.gateway, f"{site.pc_ip}/{match.group(2)} gw {match.group(3)}")
                break
            time.sleep(3)
        if site.pc_ip is None:
            self.report.check(f"{name}: wired PC got DHCP lease{suffix}", False, dhcp_output[-160:])

        # Virtual LAN host (network namespace on the CPE)
        rc, lease = cpe.run_rc(f"sh /data/vcpe/ci/cpe/netns-client.sh add {self.args.bridge} {site.netns}", timeout=90)
        fields = dict(line.split("=", 1) for line in lease.splitlines() if "=" in line)
        site.ns_ip = fields.get("IP") if rc == 0 else None
        self.report.check(f"{name}: virtual client (netns) got DHCP lease{suffix}",
                          bool(site.ns_ip) and site.ns_ip.startswith(site.lan_network + "."), lease[-200:])
        self.report.check(f"{name}: virtual client lease comes from the CPE DHCP server{suffix}",
                          fields.get("SERVER") == site.gateway, f"server={fields.get('SERVER')}")

        # Same DHCP server: both leases are in the one dnsmasq lease table
        leases = cpe.run("docker exec vcpe-forwarder sh -c 'cat /var/lib/misc/dnsmasq*.leases' 2>&1 || true")
        both = bool(site.pc_ip and site.ns_ip) and (f" {site.pc_ip} " in leases) and (f" {site.ns_ip} " in leases)
        self.report.check(f"{name}: wired and virtual leases issued by the same DHCP server{suffix}", both,
                          f"pc={site.pc_ip} netns={site.ns_ip}, {len(leases.splitlines())} leases in dnsmasq table")

        self.ns_ping(site, site.gateway, f"{name}: virtual client -> CPE gateway{suffix}")
        self.ns_ping(site, site.pc_ip, f"{name}: virtual client -> wired PC{suffix}")
        self.pc_ping(site, site.gateway, f"{name}: wired PC -> CPE gateway{suffix}")
        self.pc_ping(site, site.ns_ip, f"{name}: wired PC -> virtual client{suffix}")

    # ---------------------------------------------------------------------------------
    def configure_tunnel(self) -> None:
        """WireGuard tunnel between the two CPEs. The test acts as the Controller:
        it exchanges public keys/endpoints and routes each remote LAN via the tunnel."""
        for site in self.sites:
            output = site.console.run(TUNNEL_KEYS, timeout=60)
            values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line and line.split("=", 1)[0] in {"PUBKEY", "WAN_IP"})
            site.public_key = values.get("PUBKEY") or None
            site.wan_ip = values.get("WAN_IP") or None
            self.report.require(f"{site.name}: WAN address and WireGuard key ready",
                                bool(site.public_key and len(site.public_key) == 44 and site.wan_ip),
                                f"wan={site.wan_ip}")

        first, second = self.sites
        rc, output = first.console.run_rc(f"ping -c 3 -W 2 {second.wan_ip}", timeout=40)
        loss = re.search(r"(\d+)% packet loss", output)
        self.report.check("underlay: CPE-1 WAN -> CPE-2 WAN", rc == 0,
                          f"{first.wan_ip} -> {second.wan_ip}: {loss.group(0) if loss else output[-80:]}")

        for site, peer in ((first, second), (second, first)):
            site.tunnel_transaction = {
                "validate_only": False,
                "operations": [
                    {"method": "PUT", "path": f"/api/v1/tunnels/wireguard/{TUNNEL}", "payload": {
                        "private_key_ref": f"file://{KEY_DIR_FORWARDER}/{TUNNEL}.private",
                        "listen_port": TUNNEL_PORT,
                        "local_addresses": [f"{site.tunnel_ip}/24"],
                        "mtu": 1420,
                        "description": f"CI tunnel {site.name} <-> {peer.name}",
                    }},
                    {"method": "PUT", "path": f"/api/v1/tunnels/wireguard/{TUNNEL}/peers/{peer.name.lower()}", "payload": {
                        "public_key": peer.public_key,
                        "endpoint": f"{peer.wan_ip}:{TUNNEL_PORT}",
                        "allowed_ips": [peer.lan_cidr, f"{peer.tunnel_ip}/32"],
                        "persistent_keepalive": 25,
                        "description": f"Peer {peer.name}",
                    }},
                    {"method": "PUT", "path": f"/api/v1/routes/static/{TUNNEL}-peer-routes", "payload": {
                        "routes": [{"destination_cidr": peer.lan_cidr, "out_interface": TUNNEL}],
                    }},
                ],
            }
            applied, detail = self.apply_transaction(site, site.tunnel_transaction, "/tmp/tunnel-transaction.json")
            self.report.require(f"{site.name}: WireGuard tunnel configured through Forwarder transaction API", applied, detail)

    def test_inter_cpe(self, when: str = "") -> None:
        first, second = self.sites
        suffix = f" {when}" if when else ""

        # Tunnel endpoints (also triggers the WireGuard handshake before the measured pings).
        first.console.run_rc(f"ping -c 2 -W 2 {second.tunnel_ip}", timeout=30)
        rc, output = first.console.run_rc(f"ping -c 3 -W 2 {second.tunnel_ip}", timeout=40)
        loss = re.search(r"(\d+)% packet loss", output)
        self.report.check(f"tunnel: CPE-1 {TUNNEL} -> CPE-2 {TUNNEL}{suffix}", rc == 0 and loss is not None and loss.group(1) == "0",
                          f"{first.tunnel_ip} -> {second.tunnel_ip}: {loss.group(0) if loss else output[-80:]}")

        for site in self.sites:
            handshake = site.console.run(f"docker exec vcpe-forwarder wg show {TUNNEL} latest-handshakes 2>&1 || true")
            stamps = [int(value) for value in re.findall(r"\s(\d+)\s*$", handshake, re.M)]
            self.report.check(f"{site.name}: WireGuard handshake completed{suffix}", any(stamp > 0 for stamp in stamps),
                              handshake[-80:] or "no peers")

        for site, peer in ((first, second), (second, first)):
            route = site.console.run(f"ip route get {peer.gateway} 2>&1 || true")
            self.report.check(f"{site.name}: route to {peer.name} LAN uses the tunnel{suffix}", f"dev {TUNNEL}" in route, route[:100])

        # End-to-end across sites: wired PCs and virtual clients, both directions.
        self.pc_ping(first, second.pc_ip, f"inter-CPE: PC1 -> PC2{suffix}")
        self.pc_ping(second, first.pc_ip, f"inter-CPE: PC2 -> PC1{suffix}")
        self.ns_ping(first, second.ns_ip, f"inter-CPE: virtual client 1 -> virtual client 2{suffix}")
        self.ns_ping(second, first.ns_ip, f"inter-CPE: virtual client 2 -> virtual client 1{suffix}")
        self.pc_ping(first, second.ns_ip, f"inter-CPE: PC1 -> virtual client 2{suffix}")
        self.ns_ping(second, first.pc_ip, f"inter-CPE: virtual client 2 -> PC1{suffix}")

    # ---------------------------------------------------------------------------------
    def reboot_check(self) -> None:
        site = self.sites[0]
        cpe = site.console
        log(f"rebooting {site.name} to verify recovery")
        cpe.send("reboot\n")
        time.sleep(15)
        cpe.buf = ""
        cpe.wait_for_shell(timeout=self.args.boot_timeout)
        rc, output = cpe.run_rc(WAIT_FORWARDER, timeout=240)
        self.report.require(f"{site.name}: Forwarder came back after reboot", rc == 0, output[-200:])

        # The LAN (bridge, gateway address, DHCP) must recover without any help.
        self.verify_cpe_lan(site, "after reboot")
        self.test_lan(site, "after reboot")

        # The Forwarder does not replay tunnels by itself after a restart; in a
        # full deployment the Agent's startup reconciliation re-sends them.
        # Replay the same transaction here, as the Agent would.
        applied, detail = self.apply_transaction(site, site.tunnel_transaction, "/tmp/tunnel-transaction.json")
        self.report.check(f"{site.name}: tunnel configuration replayed after reboot", applied, detail)
        self.test_inter_cpe("after reboot")

    # ---------------------------------------------------------------------------------
    def collect_diagnostics(self) -> None:
        for site in self.sites:
            cpe = site.console
            if cpe is None or cpe.sock is None:
                continue
            try:
                cpe.drain(1.0)
                diagnostics = cpe.run(
                    "ip -br addr 2>&1\n"
                    "ip route 2>&1\n"
                    "bridge link show 2>&1\n"
                    "sysctl net.ipv4.ip_forward 2>&1\n"
                    "iptables -S FORWARD 2>&1 | head -20\n"
                    "docker ps -a 2>&1\n"
                    f"docker exec vcpe-forwarder wg show 2>&1 | grep -v 'private key'\n"
                    "docker logs --tail 60 vcpe-forwarder 2>&1\n",
                    timeout=60, check=False,
                )
                path = self.artifacts / f"diagnostics-{site.name}.txt"
                path.write_text(diagnostics, encoding="utf-8")
                log(f"diagnostics saved to {path}")
            except Exception as exc:                             # diagnostics must never mask the real failure
                log(f"{site.name}: could not collect diagnostics: {exc}")

    def finish(self) -> None:
        for site in self.sites:
            for console in (site.console, site.pc):
                if console is not None:
                    console.close()
        if self.project is None:
            return
        pid, name, after = self.project["project_id"], self.project["name"], self.args.after
        try:
            if after == "delete":
                self.gns3.delete_project(pid)
                log(f"deleted project {name}")
            elif after == "stop":
                self.gns3.stop_all(pid)
                self.gns3.close_project(pid)
                log(f"project {name} stopped and kept for inspection")
            else:
                log(f"project {name} left running")
        except InfraError as exc:
            log(f"warning: could not {after} project {name}: {exc}")

    # ---------------------------------------------------------------------------------
    def run(self) -> int:
        error: str | None = None
        try:
            self.archive = build_source_archive([
                "docker-compose.yml", "docker-compose.alpine.yml",
                "vcpe-forwarder", "vcpe-agent", "vcpe-monitoring", "ci/cpe",
            ])
            self.build_topology()
            log("provisioning both CPEs in parallel (a few minutes)")
            self.parallel(self.provision)
            for site in self.sites:
                self.test_lan(site)
            self.configure_tunnel()
            self.test_inter_cpe()
            if self.args.reboot_check:
                self.reboot_check()
        except CheckFailed:
            pass                                                 # already recorded in the report
        except InfraError as exc:
            error = str(exc)
            log(f"INFRASTRUCTURE ERROR: {exc}")
        except Exception:                                        # unexpected bug in the test itself
            error = traceback.format_exc()
            log(error)
        finally:
            try:
                if self.report.failed or error:
                    self.collect_diagnostics()
            finally:
                self.finish()

        self.report.write_junit(self.artifacts / "junit.xml", error)
        print(self.report.summary(), flush=True)
        if error:
            return 2
        return 1 if self.report.failed else 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    env = os.environ.get
    parser = argparse.ArgumentParser(description="GNS3 CI test for the vCPE SD-WAN project")
    parser.add_argument("--gns3-url", default=env("GNS3_URL"),
                        help="GNS3 server URL, e.g. http://<server>:3080 (required; or set GNS3_URL)")
    parser.add_argument("--gns3-user", default=env("GNS3_USER"))
    parser.add_argument("--gns3-password", default=env("GNS3_PASSWORD"))
    parser.add_argument("--console-host", default=env("GNS3_CONSOLE_HOST"), help="defaults to the GNS3 URL host")
    parser.add_argument("--project-name", default=env("GNS3_PROJECT_NAME"),
                        help="dedicated disposable test project; it is DELETED and rebuilt on every run "
                             "(required; protected lab projects are refused)")
    parser.add_argument("--after", choices=["stop", "keep-running", "delete"], default=env("GNS3_AFTER", "stop"),
                        help="what to do with the project when the test ends (default: stop nodes, keep project)")
    parser.add_argument("--cpe-image", default=env("CPE_IMAGE", "alpine-virt-3.18.4.qcow2"))
    parser.add_argument("--data-disk-image", default=env("CPE_DATA_DISK_IMAGE", "empty20G.qcow2"))
    parser.add_argument("--qemu-path", default=env("QEMU_PATH", "/usr/bin/qemu-system-x86_64"))
    parser.add_argument("--cpe-ram", type=int, default=int(env("CPE_RAM", "2048")))
    parser.add_argument("--cpe-cpus", type=int, default=int(env("CPE_CPUS", "2")))
    parser.add_argument("--bridge", default="br-lan")
    parser.add_argument("--lan-base", default="10.0", help="site LANs are <base>.1.0/24 and <base>.2.0/24")
    parser.add_argument("--boot-timeout", type=int, default=300)
    parser.add_argument("--build-timeout", type=int, default=1200)
    parser.add_argument("--reboot-check", action=argparse.BooleanOptionalAction, default=True,
                        help="reboot CPE-1 and verify recovery (default: on)")
    parser.add_argument("--artifacts", default=str(REPO_ROOT / "ci" / "artifacts"))
    args = parser.parse_args(argv)
    if not args.gns3_url:
        parser.error("--gns3-url (or GNS3_URL) is required")
    args.gns3_url = args.gns3_url.rstrip("/")
    if not args.project_name:
        parser.error("--project-name (or GNS3_PROJECT_NAME) is required: name the disposable project to rebuild")
    if args.project_name.strip().casefold() in PROTECTED_PROJECTS:
        parser.error(f"refusing to delete protected GNS3 project {args.project_name!r}")
    return args


# Lab projects this test must never delete or rebuild (compared case-insensitively).
PROTECTED_PROJECTS = {name.casefold() for name in (
    "SD-WAN", "Mohammad", "Thesis-LAN-Portable", "prova", "sdwan-ci",
)}


def main() -> int:
    return SdwanTest(parse_args()).run()


if __name__ == "__main__":
    sys.exit(main())
