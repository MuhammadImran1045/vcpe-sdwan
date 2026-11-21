"""Offline-only tests: fake API, fake inventories, fake Telnet sockets; no network."""
import copy
import contextlib
import io
import json
from pathlib import Path
import re
import socket
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET
import namespace_ci_operation as n
import telnet_command_executor as t

PID='11111111-1111-4111-8111-111111111111'
RULES=[{'priority':0,'src':'all','table':'local'},{'priority':32766,'src':'all','table':'main'},{'priority':32767,'src':'all','table':'default'}]
STATS='3 packets transmitted, 3 packets received, 0% packet loss\n'
SCRIPT='=== SD-WAN CI Namespace Provisioning ===\n=== Connectivity: Namespace to Host ===\n'+STATS+'=== Connectivity: Host to Namespace ===\n'+STATS+'STEP_218D_6_PASS\n'
def addr(name,ip):
    return {'ifname':name,'addr_info':[{'family':'inet','local':ip.split('/')[0],'prefixlen':int(ip.split('/')[1])}]}
def route(dev,ip):
    return [{'dst':'10.250.218.0/30','dev':dev,'protocol':'kernel','scope':'link','prefsrc':ip}]
def inventory(healthy=True):
    host={'ifname':n.HOST,'ifindex':10,'link_index':20,'link_netnsid':0,'flags':['UP'],'linkinfo':{'info_kind':'veth'}}
    peer={'ifname':n.PEER,'ifindex':20,'link_index':10,'flags':['UP'],'linkinfo':{'info_kind':'veth'}}
    return {'namespaces':[{'name':n.NS,'id':0}] if healthy else [],
     'host_links':[{'ifname':'lo','ifindex':1}]+([host] if healthy else []),
     'host_addresses':[addr('lo','127.0.0.1/8')]+([addr(n.HOST,'10.250.218.1/30')] if healthy else []),
     'host_routes':route(n.HOST,'10.250.218.1') if healthy else [],
     'host_rules':copy.deepcopy(RULES),
     'namespace_links':[{'ifname':'lo','ifindex':1,'flags':['UP']},peer],
     'namespace_addresses':[addr('lo','127.0.0.1/8'),addr(n.PEER,'10.250.218.2/30')],
     'namespace_routes':route(n.PEER,'10.250.218.2'),
     'namespace_rules':copy.deepcopy(RULES)}
class FakeAPI:
    url='http://mock.invalid:3080'
    def __init__(self):
        self.project={'project_id':PID,'name':n.PROJECT,'status':'opened'}
        self.node={'node_id':'node-1','name':n.NODE,'node_type':'qemu','status':'started','console_type':'telnet','console':5012}
        self.calls=[]
    def get(self,path):
        self.calls.append(path)
        if path=='/v2/projects': return [self.project]
        if path=='/v2/projects/'+PID: return self.project
        if path=='/v2/projects/'+PID+'/nodes': return [self.node]
        raise AssertionError(path)
class FakeConsole:
    prompt_kind='root-shell'
    def __init__(self,healthy=True):
        self.data=inventory(healthy); self.calls=[]; self.overrides={}; self.count={}; self.closed=False
    def __enter__(self): return self
    def __exit__(self,*args): self.closed=True
    def perform(self,operation,**kwargs):
        self.calls.append(operation); self.count[operation]=self.count.get(operation,0)+1
        override=self.overrides.get(operation)
        if callable(override): override=override(self)
        if isinstance(override,Exception): raise override
        if override is not None:
            output,code=override
        elif operation in self.data: output,code=json.dumps(self.data[operation]),0
        elif operation=='uid': output,code='0\n',0
        elif operation=='metadata': output,code='0 700\n',0
        elif operation=='checksum': output,code=n.SHA256+'  '+n.SCRIPT+'\n',0
        elif operation=='namespace_pids': output,code='',0
        elif operation=='provision':
            assert kwargs.get('permit') is True
            self.data=inventory(True); output,code=SCRIPT,0
        elif operation in ('namespace_to_host_ping','host_to_namespace_ping'): output,code=STATS,0
        else: raise AssertionError(operation)
        return t.CommandResult(n.COMMANDS[operation],code,output,0.,'mock')

class OperationTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(socket,'create_connection',side_effect=AssertionError('LIVE NETWORK FORBIDDEN')))
        self.stack.enter_context(patch.object(n.urllib.request.OpenerDirector,'open',side_effect=AssertionError('LIVE API FORBIDDEN')))
        self.api=FakeAPI(); self.console=FakeConsole()
    def run_case(self,provision=True,approve=True):
        return n.run(self.api,PID,lambda *a,**k:self.console,provision=provision,approve=approve)
    def check(self,report,stage,status):
        self.assertEqual(next(c['status'] for c in report['checks'] if c['name']==stage),status)
    def test_preflight_healthy_no_provision_no_ping(self):
        r=self.run_case(False)
        self.assertTrue(r['ok']); self.assertEqual(r['resource_state'],'healthy')
        for key in n.STAGES[4:]: self.assertNotIn(key,self.console.calls); self.check(r,key,'SKIP')
    def test_preflight_absent(self):
        self.console=FakeConsole(False); r=self.run_case(False)
        self.assertTrue(r['ok']); self.assertEqual(r['resource_state'],'absent')
        self.assertNotIn('namespace_links',self.console.calls)
    def test_fresh_provision(self):
        self.console=FakeConsole(False); r=self.run_case()
        self.assertTrue(r['ok']); self.assertEqual(self.console.calls.count('provision'),1)
        for key in n.STAGES: self.check(r,key,'PASS')
    def test_healthy_repeat_two_explicit_runs(self):
        for _ in range(2): self.assertTrue(self.run_case()['ok'])
        self.assertEqual(self.console.calls.count('provision'),2)
    def test_approval_required_before_api(self):
        r=self.run_case(approve=False)
        self.assertFalse(r['ok']); self.assertEqual(self.api.calls,[]); self.assertEqual(self.console.calls,[])
    def test_checksum_mismatch(self):
        self.console.overrides['checksum']=('0'*64+'  '+n.SCRIPT,0)
        r=self.run_case(); self.check(r,'script_integrity','FAIL'); self.assertNotIn('provision',self.console.calls)
    def test_checksum_changes_before_execution(self):
        self.console.overrides['checksum']=lambda c: ((n.SHA256 if c.count['checksum']==1 else 'f'*64)+'  '+n.SCRIPT,0)
        r=self.run_case(); self.check(r,'provision','FAIL'); self.assertNotIn('provision',self.console.calls)
    def test_nonzero_provision_skips_pings(self):
        self.console.overrides['provision']=('created namespace then failed',1)
        r=self.run_case(); self.check(r,'provision','FAIL'); self.assertTrue(r['partial_state_possible'])
        for stage in n.STAGES[-2:]: self.check(r,stage,'SKIP'); self.assertNotIn(stage,self.console.calls)
    def test_provision_timeout_no_retry(self):
        self.console.overrides['provision']=t.CommandTimeout('timeout',stage='command',partial_output='created namespace')
        r=self.run_case(); self.check(r,'provision','ERROR'); self.assertEqual(r['exit_code'],2)
        self.assertEqual(self.console.calls.count('provision'),1); self.assertTrue(r['partial_state_possible'])
        self.check(r,'namespace_to_host_ping','SKIP')
    def test_provision_incomplete_marker_error(self):
        self.console.overrides['provision']=t.ProtocolError('missing end',stage='command')
        r=self.run_case(); self.check(r,'provision','ERROR'); self.check(r,'host_to_namespace_ping','SKIP')
    def test_truncated_script_output_zero_status(self):
        self.console.overrides['provision']=(SCRIPT.split('=== Connectivity: Host')[0],0)
        r=self.run_case(); self.check(r,'provision','FAIL'); self.check(r,'namespace_to_host_ping','SKIP')
    def test_bare_pass_not_accepted(self):
        self.console.overrides['provision']=('STEP_218D_6_PASS\n',0)
        self.check(self.run_case(),'provision','FAIL')
    def test_partial_packet_loss_in_script(self):
        self.console.overrides['provision']=(SCRIPT.replace('3 packets received','2 packets received',1),0)
        self.check(self.run_case(),'provision','FAIL')
    def test_success_text_with_nonzero_status(self):
        self.console.overrides['provision']=(SCRIPT,1)
        self.check(self.run_case(),'provision','FAIL')
    def test_postcondition_partial_state(self):
        self.console.overrides['provision']=lambda c: (c.data.update(inventory(False)) or SCRIPT,0)
        self.check(self.run_case(),'provision','FAIL')
    def test_ping_failure_directions_independent(self):
        self.console.overrides['namespace_to_host_ping']=(STATS,1)
        r=self.run_case(); self.check(r,'provision','PASS'); self.check(r,'namespace_to_host_ping','FAIL'); self.check(r,'host_to_namespace_ping','PASS')
        self.assertEqual(r['exit_code'],1)
    def test_ping_timeout_skips_other_direction(self):
        self.console.overrides['namespace_to_host_ping']=t.CommandTimeout('timeout',stage='command')
        r=self.run_case(); self.check(r,'namespace_to_host_ping','ERROR'); self.check(r,'host_to_namespace_ping','SKIP')
    def test_json_junit_match_and_no_overwrite(self):
        self.console.overrides['provision']=('failure',1); r=self.run_case()
        with tempfile.TemporaryDirectory() as directory:
            jp,xp=n.write_reports(r,directory); second=n.write_reports(r,directory)
            self.assertNotEqual(jp,second[0]); self.assertEqual(json.loads(jp.read_text())['exit_code'],1)
            root=ET.parse(xp).getroot()
            self.assertEqual(root.attrib,{'name':'namespace-ci','tests':'7','failures':'1','errors':'0','skipped':'2'})
            self.assertIsNotNone(root.find("testcase[@name='provision']/failure"))
    def test_junit_transport_error(self):
        self.console.overrides['provision']=t.ConsoleDisconnected('lost',stage='command')
        r=self.run_case()
        with tempfile.TemporaryDirectory() as d:
            _,xp=n.write_reports(r,d); root=ET.parse(xp).getroot()
            self.assertEqual(root.get('errors'),'1'); self.assertEqual(root.get('failures'),'0')
    def test_dynamic_console_port(self):
        self.api.node['console']=54321
        found=[]
        def factory(host,port,**kwargs): found.append(port); return self.console
        r=n.run(self.api,PID,factory)
        self.assertTrue(r['ok']); self.assertEqual(found,[54321])
    def test_identity_changes_before_provision(self):
        original=self.api.get
        def get(path):
            if len(self.api.calls)>=3: self.api.node['console']=6000
            return original(path)
        self.api.get=get
        r=self.run_case(); self.check(r,'provision','FAIL'); self.assertNotIn('provision',self.console.calls)
    def test_api_failure_is_error(self):
        self.api.get=lambda path: (_ for _ in ()).throw(OSError('unavailable'))
        r=self.run_case(); self.check(r,'identity','ERROR'); self.assertEqual(self.console.calls,[])
    def test_no_remote_script_in_default_mode(self):
        self.assertNotIn('provision',self.run_case(False)['evidence'])
        self.assertNotIn('provision',self.console.calls)

# Each conflict must stop before the provisioning command is ever sent.
def conflict(mutate):
    def test(self):
        mutate(self.console)
        r=self.run_case(); self.assertFalse(r['ok']); self.assertNotIn('provision',self.console.calls)
    return test
CONFLICTS={
 'wrong_veth_type':lambda c:c.data['host_links'][1]['linkinfo'].update(info_kind='dummy'),
 'peer_type':lambda c:c.data['namespace_links'][1]['linkinfo'].update(info_kind='dummy'),
 'host_bridge':lambda c:c.data['host_links'][1].update(master='br-lan'),
 'peer_bridge':lambda c:c.data['namespace_links'][1].update(master=5),
 'peer_index':lambda c:c.data['namespace_links'][1].update(link_index=99),
 'host_peer_index':lambda c:c.data['host_links'][1].update(link_index=99),
 'namespace_id':lambda c:c.data['host_links'][1].update(link_netnsid=99),
 'missing_namespace_id':lambda c:c.data['namespaces'][0].pop('id'),
 'extra_namespace_device':lambda c:c.data['namespace_links'].append({'ifname':'eth0','ifindex':3}),
 'active_process':lambda c:c.overrides.update(namespace_pids=('123\n',0)),
 'wrong_address':lambda c:c.data['host_addresses'][1]['addr_info'][0].update(local='10.250.218.2'),
 'extra_address':lambda c:c.data['host_addresses'].append(addr(n.HOST,'192.0.2.1/24')),
 'subnet_on_eth0':lambda c:c.data['host_addresses'].append(addr('eth0','10.250.218.1/30')),
 'subnet_on_eth2':lambda c:c.data['host_addresses'].append(addr('eth2','10.250.218.5/24')),
 'subnet_on_bridge':lambda c:c.data['host_addresses'].append(addr('br-lan','10.250.218.5/24')),
 'route_conflict':lambda c:c.data['host_routes'].append({'dst':'10.0.0.0/8','dev':'eth0'}),
 'route_gateway':lambda c:c.data['host_routes'][0].update(gateway='192.0.2.1'),
 'namespace_default_route':lambda c:c.data['namespace_routes'].append({'dst':'default','gateway':'10.250.218.1'}),
 'policy_rule':lambda c:c.data['host_rules'].append({'priority':100,'table':100}),
 'namespace_rule':lambda c:c.data['namespace_rules'].append({'priority':100,'table':100}),
 'peer_name_on_host':lambda c:c.data['host_links'].append({'ifname':n.PEER,'ifindex':45}),
 'namespace_only':lambda c:c.data['host_links'].pop(),
 'host_only':lambda c:c.data.update(namespaces=[]),
 'host_down':lambda c:c.data['host_links'][1].update(flags=[]),
 'lo_down':lambda c:c.data['namespace_links'][0].update(flags=[]),
 'group_write_script':lambda c:c.overrides.update(metadata=('0 770',0)),
 'script_wrong_owner':lambda c:c.overrides.update(metadata=('1000 700',0)),
 'script_missing_symlink':lambda c:c.overrides.update(metadata=('',1)),
 'nonroot_uid':lambda c:c.overrides.update(uid=('1000',0)),
 'truncated_inventory':lambda c:c.overrides.update(host_links=('[{',0)),
 'missing_command':lambda c:c.overrides.update(host_links=('ip: not found',127)),
}
for name,mutate in CONFLICTS.items(): setattr(OperationTests,'test_conflict_'+name,conflict(mutate))
def bad_identity(field,value,project=False):
    def test(self):
        (self.api.project if project else self.api.node)[field]=value
        r=self.run_case(); self.assertFalse(r['ok']); self.assertEqual(self.console.calls,[])
    return test
for field,value,project in [('name','SD-WAN',True),('project_id','other',True),('status','closed',True),('node_type','vpcs',False),('status','stopped',False),('console_type','ssh',False),('console',0,False),('name','Other',False)]:
    setattr(OperationTests,'test_identity_'+field+str(project),bad_identity(field,value,project))

class PingTests(unittest.TestCase):
    def test_busybox_and_iputils(self):
        for output in [STATS,'3 packets transmitted, 3 received, 0% packet loss, time 2000ms\n']:
            self.assertEqual(n.ping_stats(output)['received'],3)
    def test_false_pass_statistics(self):
        for output in ['', 'PASS', STATS+STATS, STATS.replace('received','receivedx'), STATS.replace('0%','33%'),STATS.replace('3 packets received','2 packets received'), '1 packets transmitted, 1 received, 0% packet loss\n']:
            with self.subTest(output=output),self.assertRaises(n.CheckFailed): n.ping_stats(output)

class WireSocket:
    def __init__(self,mode='ok'):
        self.queue=[b'alpine:~# ']; self.sent=[]; self.closed=False; self.mode=mode
    def settimeout(self,t): pass
    def close(self): self.closed=True
    def recv(self,n):
        if self.queue:return self.queue.pop(0)
        raise socket.timeout()
    def sendall(self,data):
        self.sent.append(data)
        token=re.search(rb'S_BEGIN_([a-f0-9]+)__',data).group(1)
        begin=b'__NS_BEGIN_'+token+b'__\r\n'; end=b'__NS_END_'+token+b'__:0\r\n'
        if self.mode=='truncated': response=data+b'\n'+begin+b'partial'+end[:-2]
        elif self.mode=='echo': response=data+b'\n'
        elif self.mode=='drop': self.queue.extend([begin+b'partial',b'']); return
        elif self.mode=='invalid_status': response=begin+b'output\r\n'+end.replace(b':0',b':0oops')
        else: response=data+b'\n'+begin+b'ok\r\n'+end
        self.queue.extend(bytes([byte]) for byte in response)
class WireTests(unittest.TestCase):
    def make(self,mode='ok'):
        sock=WireSocket(mode)
        factory=patch.object(socket,'create_connection',return_value=sock); factory.start(); self.addCleanup(factory.stop)
        c=n.Console('mock.invalid',123,listen_seconds=.001); c.connect(); self.addCleanup(c.close)
        return c,sock
    def test_fragmented_unique_marker_output(self):
        c,s=self.make(); a=c.perform('uid',timeout=.1); b=c.perform('checksum',timeout=.1)
        self.assertEqual(a.output,'ok'); self.assertNotEqual(a.marker,b.marker); self.assertEqual(len(s.sent),2)
    def test_only_exact_operations(self):
        c,s=self.make()
        for operation in ['sh /root/ci-namespace.sh','reboot','provision; reboot','provision']:
            with self.assertRaises(n.CheckFailed): c.perform(operation)
        self.assertEqual(s.sent,[])
    def test_pinned_provision_command(self):
        c,s=self.make(); c.perform('provision',permit=True)
        self.assertIn(b'; sh /root/ci-namespace.sh; ns_rc=$?;',s.sent[0])
    def test_no_false_pass_echo_or_truncation(self):
        for mode in ['echo','truncated']:
            c,s=self.make(mode)
            with self.assertRaises(t.CommandTimeout):c.perform('uid',timeout=.01)
            self.assertTrue(s.closed); self.assertEqual(len(s.sent),1)
    def test_interruption(self):
        c,s=self.make('drop')
        with self.assertRaises(t.ConsoleDisconnected):c.perform('uid',timeout=.02)
        self.assertTrue(s.closed)
    def test_malformed_status(self):
        c,s=self.make('invalid_status')
        with self.assertRaises(t.ProtocolError):c.perform('uid',timeout=.02)
        self.assertTrue(s.closed)

if __name__=='__main__':unittest.main()
