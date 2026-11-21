#!/usr/bin/env python3
"""Step 218D-17: two-command console executor. No credentials or automatic retries.

Reuses the committed detector, retaining its passive Telnet negotiation policy.
Wake is opt-in. A timeout closes the session; it does not cancel a remote command.
Console output combines stdout/stderr. Use exclusively with an idle shell and no
other console clients. Prompt recognition is heuristic, not authentication.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict, dataclass
import json
import math
import os
import re
import socket
import time
import uuid
import telnet_prompt_detector as detector

ALLOWED = frozenset({'uname -a', 'cat /etc/os-release'})
SHELL_KINDS = {'root-shell', 'user-shell'}

def read_only_problem(command):
    return None if isinstance(command, str) and command in ALLOWED else 'only exact uname -a and cat /etc/os-release are allowed'

def positive(value):
    if not math.isfinite(value) or not 0 < value <= 300:
        raise ValueError('timeouts must be finite and between 0 and 300 seconds')
    return value

@dataclass
class CommandResult:
    command: str
    exit_code: int
    output: str
    duration_s: float
    marker: str
    @property
    def ok(self):
        return self.exit_code == 0
    def to_dict(self):
        return dict(asdict(self), ok=self.ok)

class ExecutorError(Exception):
    def __init__(self, message, *, stage, partial_output='', kind=None):
        super().__init__(message)
        self.stage, self.partial_output, self.kind = stage, partial_output, kind
    def to_dict(self):
        return dict(type=type(self).__name__, message=str(self), stage=self.stage,
                    partial_output=self.partial_output[-2000:], kind=self.kind)
class ConsoleUnavailable(ExecutorError): pass
class ConsoleDisconnected(ExecutorError): pass
class LoginRequired(ExecutorError): pass
class NotAtPrompt(ExecutorError): pass
class CommandTimeout(ExecutorError): pass
class CommandRejected(ExecutorError): pass
class ProtocolError(ExecutorError): pass

class TelnetCommandExecutor:
    def __init__(self, host, port, *, listen_seconds=2., wake_seconds=3.,
                 connect_timeout=10., wake=False, max_bytes=1048576):
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('invalid console port')
        self.host, self.port = host, port
        self.listen_seconds = positive(listen_seconds)
        self.wake_seconds = positive(wake_seconds)
        self.connect_timeout = positive(connect_timeout)
        if not isinstance(max_bytes, int) or max_bytes < 1:
            raise ValueError('max_bytes must be positive')
        self.wake, self.max_bytes = wake, max_bytes
        self.sock = None
        self.buffer = bytearray()
        self.prompt_kind = None
        self.bytes_sent = 0
        self.used = False

    def __enter__(self):
        self.connect()
        return self
    def __exit__(self, *args): self.close()
    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
    def _text(self):
        # Reparse the cumulative raw buffer so split IAC/UTF-8 sequences survive.
        return detector.clean_text(bytes(self.buffer))
    def _auth(self, text, stage):
        for line in text.splitlines():
            kind = detector.classify(line)
            if kind in {'login', 'password'}:
                raise LoginRequired('authentication prompt; no credentials sent',
                                    stage=stage, kind=kind, partial_output=text)
    def _send(self, payload, stage, timeout):
        try:
            self.sock.settimeout(timeout)
            self.sock.sendall(payload)
            self.bytes_sent += len(payload)
        except OSError as exc:
            raise ConsoleDisconnected(str(exc), stage=stage, partial_output=self._text()) from exc
    def _read(self, seconds, stage, stop=None):
        deadline = time.monotonic() + seconds
        while True:
            text = self._text()
            self._auth(text, stage)
            if stop and stop(text): return True
            remaining = deadline - time.monotonic()
            if remaining <= 0: return False
            self.sock.settimeout(min(remaining, .1))
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                raise ConsoleDisconnected(str(exc), stage=stage, partial_output=text) from exc
            if not data:
                raise ConsoleDisconnected('console connection closed', stage=stage, partial_output=text)
            self.buffer.extend(data)
            if len(self.buffer) > self.max_bytes:
                raise ProtocolError('console output limit exceeded', stage=stage, partial_output=self._text()[-2000:])

    def connect(self):
        if self.used:
            raise ProtocolError('session cannot be reconnected; create a new executor', stage='connect')
        self.used = True
        try:
            try:
                self.sock = socket.create_connection((self.host, self.port), self.connect_timeout)
            except OSError as exc:
                raise ConsoleUnavailable(str(exc), stage='connect') from exc
            self._read(self.listen_seconds, 'prompt')
            kind = detector.classify(self._text())
            if kind == 'silent' and self.wake:
                self._send(b'\r', 'prompt', self.connect_timeout)
                self._read(self.wake_seconds, 'prompt')
                kind = detector.classify(self._text())
            if kind not in SHELL_KINDS:
                raise NotAtPrompt('no confirmed shell prompt', stage='prompt', kind=kind,
                                  partial_output=self._text())
            self.prompt_kind = kind
            self.buffer.clear()
            return kind
        except Exception:
            self.close()
            raise

    def run(self, command, timeout=20.):
        problem = read_only_problem(command)
        if problem: raise CommandRejected(problem, stage='validation')
        positive(timeout)
        if self.sock is None or self.prompt_kind not in SHELL_KINDS:
            raise NotAtPrompt('connect to a shell first; automatic reconnect is disabled', stage='command')
        token = uuid.uuid4().hex
        begin, end = f'__CMD_BEGIN_{token}__', f'__CMD_END_{token}__'
        # Split marker literals prevent terminal echo from resembling actual output.
        # Subshell isolates the status variable and avoids changing the caller shell.
        payload = (f'( printf "\\n%s\\n" "__C""MD_BEGIN_{token}__"; '
                   f'{command}; ci_rc=$?; '
                   f'printf "\\n%s:%s\\n" "__C""MD_END_{token}__" "$ci_rc" )\r').encode('ascii')
        start_re = re.compile(r'(?m)^' + re.escape(begin) + r'\n')
        end_re = re.compile(r'(?m)^' + re.escape(end) + r':([^\n]*)\n')
        parsed = {}
        def finished(text):
            starts = list(start_re.finditer(text))
            if len(starts) > 1:
                raise ProtocolError('duplicate begin marker', stage='command', partial_output=text)
            ends = list(end_re.finditer(text))
            if len(ends) > 1:
                raise ProtocolError('duplicate completion marker', stage='command', partial_output=text)
            if not ends: return False
            if not starts or ends[0].start() < starts[0].end():
                raise ProtocolError('completion without preceding begin marker', stage='command', partial_output=text)
            status = ends[0].group(1)
            if not re.fullmatch(r'0|[1-9][0-9]{0,2}', status) or int(status) > 255:
                raise ProtocolError('invalid exit status', stage='command', partial_output=text)
            parsed.update(output=text[starts[0].end():ends[0].start()], code=int(status))
            return True
        self.buffer.clear()
        started = time.monotonic()
        try:
            self._send(payload, 'command', timeout)
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0 or not self._read(remaining, 'command', finished):
                raise CommandTimeout('completion deadline exceeded; command not cancelled',
                                     stage='command', partial_output=self._text())
            # Strip exactly the separator newline inserted before the end marker.
            output = parsed['output']
            if output.endswith('\n'): output = output[:-1]
            return CommandResult(command, parsed['code'], output,
                                 round(time.monotonic()-started, 3), token)
        except ExecutorError as exc:
            found = start_re.search(exc.partial_output)
            if found: exc.partial_output = exc.partial_output[found.end():]
            self.close()
            raise

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host')
    parser.add_argument('--port', type=int)
    parser.add_argument('--gns3-url', default=os.getenv('GNS3_URL'))
    parser.add_argument('--project')
    parser.add_argument('--node')
    parser.add_argument('--command', action='append', required=True)
    parser.add_argument('--listen', type=float, default=2.)
    parser.add_argument('--timeout', type=float, default=20.)
    parser.add_argument('--wake', action='store_true')
    parser.add_argument('--json', action='store_true')
    return parser.parse_args(argv)

def main(argv=None):
    args = parse_args(argv)
    report = dict(ok=False, results=[], error=None)
    try:
        for command in args.command:
            if read_only_problem(command):
                raise CommandRejected(read_only_problem(command), stage='validation')
        positive(args.listen); positive(args.timeout)
        direct = args.host is not None or args.port is not None
        lookup = args.project is not None or args.node is not None
        if direct == lookup: raise ValueError('choose direct host/port OR project/node')
        if direct:
            if not args.host or args.port is None: raise ValueError('host and port required')
            host, port = args.host, args.port
        else:
            if args.project != 'sdwan-ci-image-lab' or args.node != 'CPE-1':
                raise ValueError('this stage permits only sdwan-ci-image-lab / CPE-1')
            url = detector.urllib.parse.urlparse(args.gns3_url or '')
            if url.scheme not in {'http','https'} or not url.hostname or url.username or url.password:
                raise ValueError('valid GNS3_URL without embedded credentials required')
            host, port = detector.lookup_console(args.gns3_url, args.project, args.node)
        with TelnetCommandExecutor(host, port, listen_seconds=args.listen, wake=args.wake) as executor:
            report['prompt_kind'] = executor.prompt_kind
            for command in args.command:
                result = executor.run(command, args.timeout)
                report['results'].append(result.to_dict())
                if not result.ok: break
        report['ok'] = len(report['results']) == len(args.command) and all(r['ok'] for r in report['results'])
    except ExecutorError as exc:
        report['error'] = exc.to_dict()
    except (OSError, RuntimeError, ValueError) as exc:
        report['error'] = dict(type=type(exc).__name__, message=str(exc), stage='validation/lookup')
    if args.json: print(json.dumps(report, indent=2))
    else:
        for result in report['results']: print(result['output'], end='\n')
        print(json.dumps(dict(ok=report['ok'], error=report['error'])))
    return 2 if report['error'] else (0 if report['ok'] else 1)

if __name__ == '__main__':
    raise SystemExit(main())
