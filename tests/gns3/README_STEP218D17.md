# Step 218D-17: local command executor

The executor imports telnet_prompt_detector.py without changing it. It accepts
only the exact strings `uname -a` and `cat /etc/os-release`, with no write bypass.
Prompt detection and command execution share one socket. Login/password prompts
stop the run without credentials. Wake is opt-in and sends a single carriage
return only after silence; it is never sent to a known authentication prompt.

Run the current offline suite (Python 3.12, standard library only):

```powershell
python -B -m unittest discover -s tests/gns3 -p test_telnet_executor_step218d17.py -v
```

The suite mocks socket creation and blocks API discovery. No live server is used.
43 tests passed on 2026-11-21. The original untracked
`test_telnet_command_executor.py` is preserved unchanged, with a timestamped
backup. That older suite assumes broad command permissions, automatic wake and
an echo-based wire format; it is not the acceptance suite for this restricted
stage. Do not interpret broad unittest discovery as this stage's test command.

Results include command, output, exit_code, duration_s, marker and ok. CLI status:
0 all requested commands succeeded; 1 command returned nonzero; 2 validation,
authentication, protocol, connection or timeout failure. JSON failures never
report success on an empty result list. Output normalizes CRLF and strips Telnet
and terminal formatting, but retains ordinary whitespace and trailing newlines.
Output is bounded to 1 MiB per stage. All configured timeouts must be finite,
positive and no more than 300 seconds. A failed session cannot reconnect itself.

Proposed remote validation, NOT run and requiring separate approval:

```powershell
python -B tests/gns3/telnet_command_executor.py --project sdwan-ci-image-lab --node CPE-1 --command "uname -a" --json
```

Set GNS3_URL privately in the environment. GET-only discovery obtains the current
console port and refuses a closed project or stopped VM. It does not start or
open anything. No wake is enabled in this proposed command. If an idle shell
requires wake, request approval for `--wake` rather than retrying automatically.

Limitations:
- This is offline protocol validation, not validation against the current CPE.
- Like the detector, incoming Telnet options are stripped and no negotiation
  responses are sent. Consoles requiring active negotiation are unsupported.
- Shell prompt recognition is heuristic; use an idle shell with exclusive console
  access. A carriage return may submit previously typed text, so ensure no
  pending input before authorizing wake. Do not use while another client writes.
- stdout and stderr share the console. This is not a general terminal emulator;
  asynchronous console messages can be included in captured output.
- Timeout closes the local connection, but does not guarantee cancellation of a
  command already sent. No interrupts, credentials or retries are sent.
- Random markers prevent accidental collision and echoed commands from passing;
  they are not a security boundary against a malicious remote shell.
- Direct host/port mode cannot verify GNS3 identity; use project/node discovery
  for the separately approved remote validation.
- Existing CI orchestration has not been switched to this executor. No namespace
  script, topology changes, commits or pushes were performed for this step.
