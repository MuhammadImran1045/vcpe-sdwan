"""Offline Step 218D-17 tests. Socket creation and API lookup are mocked.
The older test_telnet_command_executor.py is intentionally preserved unchanged.
"""
import contextlib
import io
import json
import re
import socket
import unittest
from unittest.mock import patch
import telnet_command_executor as t

class Console:
    def __init__(self, mode='ok', banner=b'alpine:~# ', output=b'Linux alpine\r\n', code='0', fragmented=False):
        self.mode, self.output, self.code = mode, output, code
        self.fragmented = fragmented
        self.queue = [banner] if banner else []
        self.sent = []
        self.closed = False
    def settimeout(self, value): pass
    def close(self): self.closed = True
    def recv(self, size):
        if self.queue: return self.queue.pop(0)
        raise socket.timeout()
    def sendall(self, data):
        self.sent.append(data)
        if self.mode == 'send_error': raise OSError('send failed')
        if data == b'\r':
            self.queue.append(b'alpine:~# ')
            return
        token = re.search(rb'MD_BEGIN_([a-f0-9]+)__', data).group(1)
        begin = b'__CMD_BEGIN_' + token + b'__\r\n'
        end = b'__CMD_END_' + token + b'__:' + self.code.encode() + b'\r\n'
        echo = data + b'\n'
        if self.mode == 'echo_only': response = echo
        elif self.mode == 'drop':
            self.queue.extend([echo + begin + b'partial', b''])
            return
        elif self.mode == 'hang': response = echo + begin + b'partial'
        elif self.mode == 'no_begin': response = echo + end
        elif self.mode == 'no_end': response = echo + begin + self.output
        elif self.mode == 'wrong_token': response = echo + begin + b'__CMD_END_old__:0\r\n'
        elif self.mode == 'inline': response = echo + begin + b'prefix' + end
        elif self.mode == 'duplicate_begin': response = echo + begin + begin + b'\r\n' + end
        elif self.mode == 'duplicate_end': response = echo + begin + b'\r\n' + end + end
        elif self.mode == 'login': response = echo + begin + b'Password: '
        elif self.mode == 'unterminated': response = echo + begin + b'\r\n' + end.rstrip(b'\r\n')
        else: response = echo + begin + self.output + b'\r\n' + end + b'alpine:~# '
        if self.fragmented:
            self.queue.extend(bytes([x]) for x in response)
        else: self.queue.append(response)

class Tests(unittest.TestCase):
    def setUp(self):
        # Any accidental discovery or real socket connection fails the test.
        self.api = patch.object(t.detector, 'lookup_console', side_effect=AssertionError('unexpected API'))
        self.api.start()
        self.addCleanup(self.api.stop)
    def executor(self, console, **kw):
        factory = patch.object(t.socket, 'create_connection', return_value=console)
        mocked = factory.start()
        self.addCleanup(factory.stop)
        ex = t.TelnetCommandExecutor('mock.invalid', 12345, listen_seconds=.002, wake_seconds=.002, **kw)
        self.addCleanup(ex.close)
        ex.connect()
        self.assertEqual(mocked.call_count, 1)
        return ex
    def test_same_connection_multiline_and_echo(self):
        c = Console(output=b'  first\r\nsecond\r\n')
        ex = self.executor(c)
        r = ex.run('uname -a', .02)
        self.assertEqual(r.output, '  first\nsecond\n')
        self.assertTrue(r.ok)
        self.assertNotIn('__CMD_', r.output)
        self.assertIn(b'ci_rc=$?', c.sent[0])
        self.assertIn(b'printf', c.sent[0])
    def test_no_trailing_newline(self):
        self.assertEqual(self.executor(Console(output=b'abc')).run('uname -a', .02).output, 'abc')
    def test_empty_output(self):
        self.assertEqual(self.executor(Console(output=b'')).run('uname -a', .02).output, '')
    def test_unique_markers_two_commands(self):
        c = Console(); ex = self.executor(c)
        a = ex.run('uname -a', .02); b = ex.run('cat /etc/os-release', .02)
        self.assertNotEqual(a.marker,b.marker)
        self.assertEqual(len(c.sent),2)
    def test_fragmented_iac_ansi_and_utf8(self):
        c = Console(output=b'\xff\xfb\x01\x1b[31mcaf\xc3\xa9\x1b[0m\r\n', fragmented=True)
        self.assertEqual(self.executor(c).run('uname -a', .2).output, 'café\n')
    def test_fragmented_prompt_negotiation(self):
        c = Console(banner=b'')
        c.queue = [b'\xff',b'\xfb',b'\x01',b'\xff\xfa\x18',b'ignored',b'\xff',b'\xf0',b'alpine:',b'~# ']
        self.executor(c)
        self.assertEqual(c.sent, [])
    def test_old_marker_in_normal_output(self):
        r = self.executor(Console(output=b'__CMD_END_old__:0\r\n')).run('uname -a', .02)
        self.assertEqual(r.output, '__CMD_END_old__:0\n')
    def test_exit_1(self):
        r = self.executor(Console(code='1')).run('uname -a', .02)
        self.assertFalse(r.ok); self.assertEqual(r.exit_code,1)
    def test_exit_127(self):
        self.assertEqual(self.executor(Console(code='127')).run('uname -a', .02).exit_code,127)
    def test_exit_255(self):
        self.assertEqual(self.executor(Console(code='255')).run('uname -a', .02).exit_code,255)
    def test_rejected_commands_no_connection(self):
        for command in ['uname', ' uname -a', 'uname -a ', 'uname -a; reboot', 'cat /etc/shadow', 'hostname', 'mount -a', 'env', 'cat /etc/os-release\n', '', 'uname -a\x00']:
            with self.subTest(command=command), patch.object(t.socket,'create_connection') as connect:
                ex = t.TelnetCommandExecutor('mock.invalid',12345)
                with self.assertRaises(t.CommandRejected): ex.run(command)
                connect.assert_not_called()
    def test_no_write_bypass(self):
        with self.assertRaises(TypeError): t.TelnetCommandExecutor('x',123,allow_write=True)
    def test_authentication_no_bytes(self):
        for banner in [b'alpine login: ', b'Password: ', b'Password:\r\nalpine:~# ']:
            with self.subTest(banner=banner):
                c=Console(banner=banner)
                with self.assertRaises(t.LoginRequired): self.executor(c,wake=True)
                self.assertTrue(c.closed); self.assertEqual(c.sent,[])
    def test_vpcs_rejected_no_wake(self):
        c=Console(banner=b'PC1> ')
        with self.assertRaises(t.NotAtPrompt): self.executor(c,wake=True)
        self.assertEqual(c.sent,[])
    def test_unknown_rejected_no_wake(self):
        c=Console(banner=b'partial input')
        with self.assertRaises(t.NotAtPrompt): self.executor(c,wake=True)
        self.assertEqual(c.sent,[])
    def test_silent_no_wake_by_default(self):
        c=Console(banner=b'')
        with self.assertRaises(t.NotAtPrompt): self.executor(c)
        self.assertEqual(c.sent,[])
    def test_explicit_wake_once(self):
        c=Console(banner=b''); self.executor(c,wake=True)
        self.assertEqual(c.sent,[b'\r'])
    def test_eof_before_prompt(self):
        c=Console(); c.queue=[b'']
        with self.assertRaises(t.ConsoleDisconnected): self.executor(c)
        self.assertTrue(c.closed)
    def test_connect_refused(self):
        with patch.object(t.socket,'create_connection',side_effect=OSError('refused')):
            with self.assertRaises(t.ConsoleUnavailable): t.TelnetCommandExecutor('x',123).connect()
    def test_timeout_invalidates_session_without_interrupt_or_retry(self):
        c=Console(mode='hang'); ex=self.executor(c)
        with self.assertRaises(t.CommandTimeout) as err: ex.run('uname -a',.01)
        self.assertIn('partial',err.exception.partial_output)
        self.assertTrue(c.closed)
        with self.assertRaises(t.NotAtPrompt): ex.run('uname -a',.01)
        with self.assertRaises(t.ProtocolError): ex.connect()
        self.assertEqual(len(c.sent),1)
        self.assertNotIn(b'\x03', c.sent[0])
    def test_output_limit(self):
        c=Console(output=b'a'*2000); ex=self.executor(c,max_bytes=1000)
        with self.assertRaises(t.ProtocolError): ex.run('uname -a',.02)
        self.assertTrue(c.closed)
    def test_invalid_timeout(self):
        for timeout in [0,-1,float('nan'),float('inf'),301]:
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError): t.TelnetCommandExecutor('x',123,listen_seconds=timeout)
    def cli(self,c,extra=None):
        out=io.StringIO()
        with patch.object(t.socket,'create_connection',return_value=c), contextlib.redirect_stdout(out):
            status=t.main(['--host','mock.invalid','--port','12345','--listen','.002','--timeout','.02', '--command','uname -a','--json']+(extra or []))
        return status,json.loads(out.getvalue())
    def test_cli_json_pass(self):
        status,r=self.cli(Console())
        self.assertEqual(status,0); self.assertTrue(r['ok']); self.assertEqual(len(r['results']),1)
    def test_cli_nonzero_stops_second_command(self):
        c=Console(code='1'); status,r=self.cli(c,['--command','cat /etc/os-release'])
        self.assertEqual(status,1); self.assertFalse(r['ok']); self.assertEqual(len(c.sent),1)
    def test_cli_auth_json_failure(self):
        status,r=self.cli(Console(banner=b'Password: '))
        self.assertEqual(status,2); self.assertFalse(r['ok']); self.assertEqual(r['results'],[])
    def test_cli_validation_json_no_connection(self):
        with patch.object(t.socket,'create_connection') as connect:
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                status=t.main(['--host','x','--port','123','--command','reboot','--json'])
            self.assertEqual(status,2); self.assertFalse(json.loads(out.getvalue())['ok']); connect.assert_not_called()
    def test_wrong_project_never_looked_up(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            status=t.main(['--project','SD-WAN','--node','CPE-1','--command','uname -a','--json'])
        self.assertEqual(status,2); self.assertFalse(json.loads(out.getvalue())['ok'])

# Each false-PASS scenario is a separate named test.
def failure_case(mode, error, code='0'):
    def test(self):
        c=Console(mode=mode,code=code); ex=self.executor(c)
        with self.assertRaises(error): ex.run('uname -a',.01)
        self.assertTrue(c.closed)
    return test
for mode in ['echo_only','no_end','wrong_token','inline','unterminated']:
    setattr(Tests,'test_false_pass_'+mode,failure_case(mode,t.CommandTimeout))
for mode in ['no_begin','duplicate_begin','duplicate_end']:
    setattr(Tests,'test_false_pass_'+mode,failure_case(mode,t.ProtocolError))
for code in ['256','-1','0garbage','00','']:
    setattr(Tests,'test_invalid_status_'+(code or 'empty'),failure_case('ok',t.ProtocolError,code))
setattr(Tests,'test_mid_command_disconnect',failure_case('drop',t.ConsoleDisconnected))
setattr(Tests,'test_mid_command_auth',failure_case('login',t.LoginRequired))
setattr(Tests,'test_send_error',failure_case('send_error',t.ConsoleDisconnected))

if __name__=='__main__': unittest.main()
