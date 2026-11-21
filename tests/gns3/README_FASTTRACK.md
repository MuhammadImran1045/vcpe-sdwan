# SD-WAN CI — fast-track runner

This adds a **single entry point** to the existing `vcpe-sdwan/tests/gns3/` scripts already tested in the university lab.

## What it actually does

| Mode | Actions | Changes the lab? |
|---|---|---|
| `plan` (default) | Confirms `sdwan-ci`, checks 8 nodes/7 links, verifies expected CPE virtual hardware, compares live topology to your saved snapshot | **No** |
| `verify` | All `plan` checks, then the existing tested `gns3_console.py --test-cross` in both directions | **No** (sends read-only ICMP packets) |
| `repair --allow-cpe-changes` | All `plan` checks, opens the project if needed, starts stopped **existing** CPEs, repairs known `eth1` underlay and remote LAN routes, runs the tested namespace recovery script, then performs `--test-cross` | **Yes**, but only for the 2 existing CPEs in the dedicated project |

Every execution saves a JSON and JUnit XML report in `tests/gns3/test-results/` (already ignored by your `tests/gns3/.gitignore`). The report records the local Git commit, which **does not prove** that the Docker image inside the CPE is built from that commit.

**Important limitations:** This does **not** rebuild GNS3 nodes or disks from scratch, test WireGuard/SD-WAN overlay traffic, automatically deploy the latest source, or construct a reusable golden image. Those are separate remaining milestones. Do **not** delete or reset your working CPE QEMU linked clones. The university's `Mohammad` project is never targeted.

## Install the new file

Copy `ci_fast_runner.py` into:

```text
C:\Users\admin\vcpe-sdwan\tests\gns3\ci_fast_runner.py
```

Keep the existing working files in the same directory:

```text
gns3_live_compare.py
gns3_console.py
setup_namespace.sh
requirements.txt
```

Keep the saved snapshot on your Windows laptop:

```text
C:\Users\admin\sdwan-ci\current-topology.json
```

Install dependencies only if needed: `py -m pip install -r "$HOME\vcpe-sdwan\tests\gns3\requirements.txt"`.

## Windows PowerShell — run

First set the two environment variables **in your own PowerShell**, using the lab values you previously verified. Do not commit those values to your public GitHub fork.

```powershell
$env:GNS3_URL="http://YOUR_GNS3_HOST:3080"
$env:GNS3_PROJECT_ID="YOUR_DEDICATED_CI_PROJECT_UUID"
```

**1. Safe preflight (recommended first):**

```powershell
py "$HOME\vcpe-sdwan\tests\gns3\ci_fast_runner.py"
```

**2. One-command read-only full connectivity check:**

```powershell
py "$HOME\vcpe-sdwan\tests\gns3\ci_fast_runner.py" --mode verify
```

**3. Controlled repair + tests** (only on your authorized `sdwan-ci` CPEs):

```powershell
py "$HOME\vcpe-sdwan\tests\gns3\ci_fast_runner.py" --mode repair --allow-cpe-changes
```

Close the active CPE Telnet console tabs in MobaXterm before `verify` or `repair`. Do not stop the VMs themselves. Repair will stop without changing the lab if the saved topology, CPE hardware, LAN addresses, or current routes are unexpected. A partial repair can be left behind if a later check fails; inspect the report, do not blindly retry.

## Remaining work toward Giacomo's complete requirement

1. **Golden image / provisioning:** In an isolated authorized environment, create a reusable Alpine CPE template with Docker, the `/data` disk layout, Forwarder dependencies, and *no live keys or runtime state*. First prove a disposable VM boots and configures from it. A live linked clone is **not** automatically a reusable base image; do not copy its private keys into the template.
2. **Clean rebuild builder:** Only after a tested template exists, add a guarded process that recreates the eight nodes and seven links in the same dedicated project. Maintain a verified rollback/recovery path before permitting any delete/reset.
3. **Latest commit:** Provision the CPE software from a pinned source revision and record that revision/image digest for reproducible CI.
4. **Integration:** Run this wrapper's tests after provisioning, add actual SD-WAN overlay tests, produce reports, and connect it to an authorized isolated runner if required.

The preconfigured-image strategy saves time **only after** its reproducibility and security are verified.
