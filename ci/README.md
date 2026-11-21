# GNS3 SD-WAN connectivity CI

The integration test rebuilds the dedicated sdwan-ci GNS3 project with two Alpine CPEs. It builds
the forwarder from the checkout, configures the LANs and a WireGuard tunnel,
and verifies DHCP and traffic between the wired and namespace clients.

## Topology

Each site contains a NAT node, an Alpine CPE, an Ethernet switch and a VPCS PC.
CPE eth0 connects to NAT, eth1 is spare, and eth2 connects to its LAN switch.

- Site 1 uses 10.0.1.0/24 and namespace ci-lan1.
- Site 2 uses 10.0.2.0/24 and namespace ci-lan2.
- Each bridge is br-lan, with gateway .1 and DHCP pool .100 through .200.
- A WireGuard tunnel connects the sites over their NAT-facing addresses.

The GNS3 NAT networks must allow the two CPE WAN addresses to communicate.
The test programs the forwarder API directly. It exercises the forwarder data
plane and simulates configuration delivery by the controller. Agent and
controller integration require a separate test.

## Checks

1. Delete the previous dedicated test project, then recreate its nodes and links.
2. Provision Docker and iproute2 on each CPE using its serial console.
3. Upload the checkout, verify its checksum, build the forwarder and check health.
4. Configure the bridge, physical port, gateway and DHCP through transactions.
5. Request leases for the wired PC and namespace and compare the DHCP evidence.
6. Ping each gateway and check wired-to-namespace traffic in both directions.
7. Configure WireGuard keys, peers and remote LAN routes.
8. Verify handshakes, routing and cross-site traffic.
9. Reboot CPE-1 and verify automatic bridge/address/DHCP recovery.
10. Recreate the namespace for the test, replay the tunnel configuration, and
    repeat connectivity checks.

The reboot stage tests LAN recovery automatically. Namespace creation and
tunnel replay are driven by the harness, so this stage does not assert
automatic namespace or tunnel recovery.

## Running locally

Use Python 3.9 or later with access to the GNS3 HTTP API and TCP console ports.
The test uses the Python standard library. The GNS3 server must have the
Alpine root-autologin image and a disposable blank data image available.

    python ci/gns3_ci.py --gns3-url http://<gns3-server>:3080 --project-name <disposable-project> --after stop

The server URL and project name can also come from the GNS3_URL and
GNS3_PROJECT_NAME environment variables. Keep the real server address out of
committed files.

Defaults are alpine-virt-3.18.4.qcow2 and empty20G.qcow2. Each CPE uses a linked
clone and formats its second virtual disk for CI provisioning.

Useful arguments:

| Argument | Purpose |
| --- | --- |
| --project-name NAME | Required. Disposable project deleted and rebuilt on each run (or set GNS3_PROJECT_NAME). SD-WAN, Mohammad, Thesis-LAN-Portable, prova and sdwan-ci are refused. |
| --after delete | Delete only the project created by this invocation. |
| --after stop | Stop and retain the new project for inspection, the default. |
| --after keep-running | Keep the new project running for debugging. |
| --no-reboot-check | Skip the reboot stage. |
| --console-host HOST | Override the host used for serial TCP connections. |
| --lan-base 10.0 | Set the first two octets of the two /24 LANs. |
| --artifacts PATH | Choose a separate directory for logs and JUnit XML. |

Each run replaces the named project before building the topology. Use a name
reserved for this test and run one invocation at a time. The GitHub
workflow serializes its runs. A terminated run can leave the test project
for the next run to replace.
Exit codes are 0 for success, 1 for failed assertions and 2 for infrastructure
errors.

## GitHub Actions

The workflow in .github/workflows/gns3-ci.yml uses a self-hosted runner labelled
gns3. This runner needs Python on PATH and access to the lab network.
The Python script is the initial deliverable. The included GitHub workflow is available for later integration.
Configure repository variables GNS3_URL and GNS3_PROJECT_NAME (required) and, when required, repository secrets
GNS3_USER and GNS3_PASSWORD. Trigger the workflow manually or through a push
to main or a pull request. Workflow execution in GitHub requires the files
to be committed and the runner to be registered.

The workflow deletes its own project at completion. It uploads console logs,
diagnostics on failure and junit.xml even when the test fails. Read failures
and infrastructure errors in the report before treating a run as successful.

## Files and evidence

- ci/gns3_ci.py implements API access, provisioning and assertions.
- ci/cpe/netns-client.sh creates or removes a DHCP namespace client.
- docker-compose.alpine.yml maps Alpine WAN interface names.
- ci/artifacts contains generated reports and logs and is ignored by Git.
- junit.xml records individual checks and infrastructure errors.
- console-CPE-1.log and console-CPE-2.log capture serial output.
- console-PC1.log and console-PC2.log capture client tests.
- diagnostics-CPE-1.txt and diagnostics-CPE-2.txt are collected after failure.

Validation results are evidence for the specific checkout and lab run.
Earlier single-site reports may remain in the artifact directory.

The test builds the current checkout. To test the latest commit or release, check out that revision before invoking the script. The GitHub workflow uses actions/checkout for its triggering revision.


