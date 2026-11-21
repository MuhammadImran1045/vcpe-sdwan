#!/usr/bin/env python3
"""Dedicated Step 218D-19 operation; default mode is read-only preflight.

No generic command API or automatic repairs/retries. Remote execution requires
--mode provision --approve-provision, and is never part of the offline suite.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request
import uuid
from xml.etree import ElementTree as ET
import telnet_command_executor as transport

PROJECT = 'sdwan-ci-image-lab'
NODE = 'CPE-1'
NS, HOST, PEER = 'ci-test218', 'ci-veth-h', 'ci-veth-n'
SCRIPT = '/root/ci-namespace.sh'
SHA256 = 'db61535b4dce6f2c6a6c99ec811d9be89200857534b8ad2062e37b5015e3d554'
NET = ipaddress.ip_network('10.250.218.0/30')
COMMANDS = {
 'uid': 'id -u',
 'metadata': "test -f /root/ci-namespace.sh && test ! -L /root/ci-namespace.sh && stat -c '%u %a' /root/ci-namespace.sh",
 'checksum': 'sha256sum /root/ci-namespace.sh',
 'namespaces': 'ip -j netns list',
 'host_links': 'ip -j -d link show',
 'host_addresses': 'ip -j -4 addr show',
 'host_routes': 'ip -j -4 route show table all',
 'host_rules': 'ip -j -4 rule show',
 'namespace_links': 'ip netns exec ci-test218 ip -j -d link show',
 'namespace_addresses': 'ip netns exec ci-test218 ip -j -4 addr show',
 'namespace_routes': 'ip netns exec ci-test218 ip -j -4 route show table all',
 'namespace_rules': 'ip netns exec ci-test218 ip -j -4 rule show',
 'namespace_pids': 'ip netns pids ci-test218',
 'provision': 'sh /root/ci-namespace.sh',
 'namespace_to_host_ping': 'ip netns exec ci-test218 ping -c 3 -W 2 10.250.218.1',
 'host_to_namespace_ping': 'ping -c 3 -W 2 10.250.218.2',
}

class CheckFailed(Exception): pass

def require(condition, message):
    if not condition: raise CheckFailed(message)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise CheckFailed('API redirect refused')

class API:
    def __init__(self, url):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme in ('http','https') and parsed.hostname and not parsed.username
                and not parsed.password and not parsed.query and not parsed.fragment
                and parsed.path in ('','/'), 'invalid API URL')
        self.url = url.rstrip('/')
        self.opener = urllib.request.build_opener(NoRedirect())
    def get(self, path):
        with self.opener.open(urllib.request.Request(self.url + path, method='GET'), timeout=15) as response:
            data = response.read(2097153)
        require(len(data) <= 2097152, 'API output too large')
        return json.loads(data)

def identity(api, project_id):
    require(str(uuid.UUID(project_id)) == project_id, 'invalid project UUID')
    projects = api.get('/v2/projects')
    require(isinstance(projects,list), 'project list malformed')
    matches = [p for p in projects if p.get('name') == PROJECT]
    require(len(matches)==1 and matches[0].get('project_id')==project_id, 'project name/ID mismatch or duplicate')
    p = api.get('/v2/projects/' + project_id)
    require(p.get('name')==PROJECT and p.get('project_id')==project_id and p.get('status')=='opened', 'project not exactly matched and opened')
    nodes = api.get('/v2/projects/' + project_id + '/nodes')
    require(isinstance(nodes,list), 'node list malformed')
    matches = [n for n in nodes if n.get('name')==NODE]
    require(len(matches)==1, 'CPE-1 missing or duplicated')
    n=matches[0]
    require(n.get('node_type')=='qemu' and n.get('status')=='started' and n.get('console_type')=='telnet', 'node is not a started QEMU Telnet node')
    require(isinstance(n.get('node_id'),str) and bool(n['node_id']), 'node ID missing')
    port=n.get('console')
    require(type(port) is int and 0<port<65536, 'invalid console port')
    host=n.get('console_host')
    if host in (None,'','0.0.0.0','::'): host=urllib.parse.urlsplit(api.url).hostname
    require(isinstance(host,str) and bool(host), 'console host missing')
    return {'project_id':project_id,'node_id':n['node_id'],'host':host,'port':port}

class Console(transport.TelnetCommandExecutor):
    """Shares the unchanged detector/connection implementation.

Framing is scoped here because the original executor intentionally admits only
uname/os-release. There is no process-global allowlist patch and no write bypass.
"""
    def perform(self, operation, *, permit=False, timeout=20):
        require(operation in COMMANDS, 'unknown operation')
        require(operation != 'provision' or permit, 'provision operation not armed')
        require(self.sock is not None and self.prompt_kind=='root-shell', 'authenticated root shell required')
        transport.positive(timeout)
        command=COMMANDS[operation]
        token=uuid.uuid4().hex
        begin=f'__NS_BEGIN_{token}__'; end=f'__NS_END_{token}__'
        # Controlled PATH in a subshell; no persistent shell/environment changes.
        wrapped=(f'( PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; '
                 f'printf "\\n%s\\n" "__N""S_BEGIN_{token}__"; '
                 f'{command}; ns_rc=$?; printf "\\n%s:%s\\n" "__N""S_END_{token}__" "$ns_rc" )\r')
        start_re=re.compile(r'(?m)^'+re.escape(begin)+r'\n')
        end_re=re.compile(r'(?m)^'+re.escape(end)+r':([^\n]*)\n')
        captured={}
        def complete(text):
            starts=list(start_re.finditer(text)); ends=list(end_re.finditer(text))
            if len(starts)>1 or len(ends)>1:
                raise transport.ProtocolError('duplicate marker',stage='command',partial_output=text)
            if not ends: return False
            if not starts or ends[0].start()<starts[0].end():
                raise transport.ProtocolError('end without begin',stage='command',partial_output=text)
            code=ends[0].group(1)
            if not re.fullmatch(r'0|[1-9][0-9]{0,2}',code) or int(code)>255:
                raise transport.ProtocolError('invalid exit status',stage='command',partial_output=text)
            output=text[starts[0].end():ends[0].start()]
            captured.update(output=output[:-1] if output.endswith('\n') else output,code=int(code))
            return True
        self.buffer.clear(); started=time.monotonic()
        try:
            self._send(wrapped.encode('ascii'),'command',timeout)
            remaining=timeout-(time.monotonic()-started)
            if remaining<=0 or not self._read(remaining,'command',complete):
                raise transport.CommandTimeout('command completion uncertain; no retry or cancellation',stage='command',partial_output=self._text())
            return transport.CommandResult(command,captured['code'],captured['output'],time.monotonic()-started,token)
        except transport.ExecutorError:
            self.close()
            raise

def execute(console, operation, evidence, **kwargs):
    r=console.perform(operation,**kwargs)
    evidence.append(r.to_dict())
    require(r.exit_code==0, f'{operation} exited {r.exit_code}')
    return r.output

def json_list(console, operation, evidence):
    raw=execute(console,operation,evidence)
    try: data=json.loads(raw)
    except ValueError as exc: raise CheckFailed(f'{operation}: invalid or truncated JSON') from exc
    require(isinstance(data,list) and all(isinstance(x,dict) for x in data),f'{operation}: expected object list')
    return data

def checksum(console,evidence):
    require(execute(console,'uid',evidence).strip()=='0','root UID required')
    meta=execute(console,'metadata',evidence).strip().split()
    require(len(meta)==2 and meta[0]=='0' and re.fullmatch(r'[0-7]{3,4}',meta[1]),'script must be root-owned regular non-symlink')
    require(int(meta[1],8)&0o022==0,'script writable by group/other')
    expected=SHA256+'  '+SCRIPT
    require(execute(console,'checksum',evidence).strip()==expected,'reviewed script checksum mismatch')

def index_links(links):
    result={}
    for link in links:
        name=link.get('ifname')
        require(isinstance(name,str) and name not in result,'duplicate/malformed interface names')
        require(type(link.get('ifindex')) is int,'missing interface index')
        result[name]=link
    return result

def check_rules(rules):
    expected={(0,'local'),(32766,'main'),(32767,'default')}
    normalized=[]
    for rule in rules:
        require(rule.get('src','all')=='all' and rule.get('dst','all')=='all','policy rule selectors unsupported')
        require(not any(k in rule for k in ('fwmark','iif','oif','goto','not','suppress_prefixlength')), 'custom policy rule unsupported')
        table={255:'local',254:'main',253:'default'}.get(rule.get('table'),rule.get('table'))
        normalized.append((rule.get('priority'),table))
    require(len(normalized)==3 and set(normalized)==expected,'custom or incomplete routing rules; ownership ambiguous')

def check_addresses(addresses, target, expected, namespace=False):
    seen=[]
    for interface in addresses:
        name=interface.get('ifname')
        require(isinstance(name,str) and isinstance(interface.get('addr_info'),list),'malformed address inventory')
        for address in interface['addr_info']:
            require(address.get('family')=='inet','expected IPv4 address data')
            try: ip=ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}")
            except (KeyError,ValueError) as exc: raise CheckFailed('invalid IPv4 address') from exc
            if name==target:
                require(str(ip)==expected,'target has unexpected address')
                seen.append(str(ip))
            elif ip.network.overlaps(NET):
                raise CheckFailed('subnet already used on another interface')
            elif namespace:
                require(name=='lo' and str(ip)=='127.0.0.1/8','unexpected namespace address')
    require(seen==[expected] if expected else not seen,'missing/duplicate target address')

def check_routes(routes,target,local,namespace=False):
    direct=0
    for route in routes:
        dst=route.get('dst')
        require(isinstance(dst,str),'route destination missing')
        if dst=='default':
            require(not namespace,'namespace default route is unexpected')
            continue
        try: network=ipaddress.ip_network(dst,strict=False)
        except ValueError as exc: raise CheckFailed('invalid route destination') from exc
        if not network.overlaps(NET):
            if namespace: require(network.subnet_of(ipaddress.ip_network('127.0.0.0/8')),'unrelated namespace route')
            continue
        require(target and route.get('dev')==target,'subnet route conflicts with another device')
        require(not any(k in route for k in ('gateway','multipath','nhid','encap')), 'indirect subnet route')
        table={254:'main',255:'local'}.get(route.get('table','main'),route.get('table','main'))
        kind=route.get('type','unicast')
        if network==NET:
            require(table=='main' and kind=='unicast' and route.get('protocol')=='kernel' and route.get('scope')=='link','unexpected connected subnet route')
            direct+=1
        else:
            require(network.prefixlen==32 and str(network.network_address) in (local,'10.250.218.0','10.250.218.3') and table=='local' and kind in ('local','broadcast') and route.get('protocol')=='kernel','unexpected overlapping route')
        require(route.get('prefsrc',local)==local,'route source mismatch')
    require(direct==(1 if target else 0),'missing/duplicate connected subnet route')

def inventory(console,evidence):
    names=json_list(console,'namespaces',evidence)
    require(all(isinstance(n.get('name'),str) for n in names),'namespace inventory malformed')
    require(len({n['name'] for n in names})==len(names),'duplicate namespace names')
    matching=[n for n in names if n['name']==NS]
    links=index_links(json_list(console,'host_links',evidence))
    addresses=json_list(console,'host_addresses',evidence)
    routes=json_list(console,'host_routes',evidence)
    check_rules(json_list(console,'host_rules',evidence))
    require(PEER not in links,'namespace peer name already present on host')
    exists=HOST in links
    require(bool(matching)==exists,'partial namespace/veth state; no automatic repair')
    if not exists:
        check_addresses(addresses,HOST,None)
        check_routes(routes,None,None)
        return 'absent'
    host=links[HOST]
    inner=index_links(json_list(console,'namespace_links',evidence))
    require(set(inner)=={'lo',PEER},'namespace contains unrelated or missing interfaces')
    peer=inner[PEER]
    require(execute(console,'namespace_pids',evidence).strip()=='','namespace has active processes; ownership ambiguous')
    for link in (host,peer):
        require(link.get('linkinfo',{}).get('info_kind')=='veth','target interface is not veth')
        require(not link.get('master'),'target belongs to a bridge/master')
        require('UP' in link.get('flags',[]),'existing target not UP; reject partial state')
    require(host.get('link_index')==peer['ifindex'] and peer.get('link_index')==host['ifindex'],'veth peer indices do not match')
    nsid=matching[0].get('id')
    require(type(nsid) is int and nsid>=0 and host.get('link_netnsid')==nsid,'host peer namespace identity not proven')
    require('UP' in inner['lo'].get('flags',[]),'namespace loopback down; partial state')
    check_addresses(addresses,HOST,'10.250.218.1/30')
    check_routes(routes,HOST,'10.250.218.1')
    check_addresses(json_list(console,'namespace_addresses',evidence),PEER,'10.250.218.2/30',True)
    check_routes(json_list(console,'namespace_routes',evidence),PEER,'10.250.218.2',True)
    check_rules(json_list(console,'namespace_rules',evidence))
    return 'healthy'

PING_STATS=re.compile(r'(?m)^[ \t]*(\d+)[ \t]+packets?[ \t]+transmitted,[ \t]*(\d+)[ \t]+(?:packets?[ \t]+)?received,[ \t]*(\d+(?:\.\d+)?)%[ \t]+packet[ \t]+loss(?:,[^\r\n]*)?[ \t]*\r?$')
def ping_stats(output):
    matches=list(PING_STATS.finditer(output))
    require(len(matches)==1,'missing, truncated or duplicate ping statistics')
    tx,rx,loss=matches[0].groups()
    require(int(tx)==3 and int(rx)==3 and float(loss)==0,'ping requires 3 sent, 3 received, 0% loss')
    return {'transmitted':3,'received':3,'loss_percent':0}

def script_sections(output):
    labels=['=== SD-WAN CI Namespace Provisioning ===','=== Connectivity: Namespace to Host ===','=== Connectivity: Host to Namespace ===','STEP_218D_6_PASS']
    lines=output.splitlines()
    require(all(lines.count(x)==1 for x in labels),'script section markers incomplete or duplicated')
    indices=[lines.index(x) for x in labels]
    require(indices==sorted(indices) and indices[0]==0 and indices[-1]==len(lines)-1,'script markers out of order or trailing output')
    ping_stats('\n'.join(lines[indices[1]+1:indices[2]]))
    ping_stats('\n'.join(lines[indices[2]+1:indices[3]]))

STAGES=['identity','console','script_integrity','resource_preflight','provision','namespace_to_host_ping','host_to_namespace_ping']
def run(api,project_id,console_factory,*,provision=False,approve=False,wake=False):
    report={'ok':False,'mode':'provision' if provision else 'preflight','script_sha256':SHA256,'checks':[], 'evidence':[], 'partial_state_possible':False}
    current='identity'
    try:
        require(not provision or approve,'provision requires explicit approval flag')
        first=identity(api,project_id)
        report['checks'].append({'name':current,'status':'PASS'})
        current='console'
        with console_factory(first['host'],first['port'],wake=wake) as console:
            require(console.prompt_kind=='root-shell','root shell required')
            report['checks'].append({'name':current,'status':'PASS'})
            current='script_integrity'; checksum(console,report['evidence'])
            report['checks'].append({'name':current,'status':'PASS'})
            current='resource_preflight'; state=inventory(console,report['evidence'])
            report['resource_state']=state
            report['checks'].append({'name':current,'status':'PASS','detail':state})
            if provision:
                current='provision'
                require(identity(api,project_id)==first,'GNS3 identity or console changed during preflight')
                checksum(console,report['evidence'])
                require(inventory(console,report['evidence'])==state,'resource state changed during preflight')
                # Final integrity check immediately before the only provisioning command.
                checksum(console,report['evidence'])
                report['partial_state_possible']=True
                output=execute(console,'provision',report['evidence'],permit=True,timeout=60)
                script_sections(output)
                require(inventory(console,report['evidence'])=='healthy','post-provision state not healthy')
                report['checks'].append({'name':current,'status':'PASS'})
                for current in ('namespace_to_host_ping','host_to_namespace_ping'):
                    try:
                        output=execute(console,current,report['evidence'],timeout=15)
                        stats=ping_stats(output)
                        report['checks'].append({'name':current,'status':'PASS','statistics':stats})
                    except CheckFailed as exc:
                        report['checks'].append({'name':current,'status':'FAIL','detail':str(exc)})
                report['partial_state_possible']=False
    except CheckFailed as exc:
        report['checks'].append({'name':current,'status':'FAIL','detail':str(exc)})
    except (transport.ExecutorError,OSError,ValueError,KeyError,TypeError) as exc:
        detail=exc.to_dict() if isinstance(exc,transport.ExecutorError) else {'type':type(exc).__name__,'message':str(exc)}
        report['checks'].append({'name':current,'status':'ERROR','detail':detail})
    completed={c['name'] for c in report['checks']}
    for stage in STAGES:
        if stage not in completed:
            report['checks'].append({'name':stage,'status':'SKIP','detail':'preflight only' if not provision and stage in STAGES[4:] else 'prerequisite failed; not executed'})
    report['ok']=not any(c['status'] in ('FAIL','ERROR') for c in report['checks'])
    report['exit_code']=2 if any(c['status']=='ERROR' for c in report['checks']) else (0 if report['ok'] else 1)
    return report

def write_reports(report,directory):
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True)
    stem='namespace-'+uuid.uuid4().hex
    jp=directory/(stem+'.json'); xp=directory/(stem+'.xml')
    with jp.open('x',encoding='utf-8') as f: json.dump(report,f,indent=2)
    checks=report['checks']
    suite=ET.Element('testsuite',name='namespace-ci',tests=str(len(checks)),failures=str(sum(c['status']=='FAIL' for c in checks)),errors=str(sum(c['status']=='ERROR' for c in checks)),skipped=str(sum(c['status']=='SKIP' for c in checks)))
    for check in checks:
        case=ET.SubElement(suite,'testcase',classname='sdwan.namespace',name=check['name'])
        tag={'FAIL':'failure','ERROR':'error','SKIP':'skipped'}.get(check['status'])
        if tag: ET.SubElement(case,tag,message=str(check.get('detail',''))).text=json.dumps(check.get('detail',''))
    with xp.open('xb') as f: ET.ElementTree(suite).write(f,encoding='utf-8',xml_declaration=True)
    return jp,xp

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['preflight','provision'],default='preflight')
    parser.add_argument('--approve-provision',action='store_true')
    parser.add_argument('--wake',action='store_true')
    parser.add_argument('--report-dir',type=Path,default=Path('namespace-ci-results'))
    args=parser.parse_args(argv)
    try:
        require(not args.approve_provision or args.mode=='provision','approval flag only valid in provision mode')
        api=API(os.environ.get('GNS3_URL',''))
        report=run(api,os.environ.get('GNS3_PROJECT_ID',''),Console,provision=args.mode=='provision',approve=args.approve_provision,wake=args.wake)
    except (CheckFailed,ValueError) as exc:
        report={'ok':False,'exit_code':1,'checks':[{'name':'configuration','status':'FAIL','detail':str(exc)}]}
    paths=write_reports(report,args.report_dir)
    print(json.dumps(report,indent=2))
    print('Reports: '+str(paths[0])+' ; '+str(paths[1]))
    return report['exit_code']

if __name__=='__main__': raise SystemExit(main())
