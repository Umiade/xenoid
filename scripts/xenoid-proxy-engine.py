#!/usr/bin/python3
"""Root-only, exact-manifest Xenoid transparent proxy engine helper."""
from __future__ import annotations
import concurrent.futures
import argparse, array, binascii, fcntl, grp, hashlib, ipaddress, json, os, platform, pwd, re
import select, signal, socket, stat, struct, subprocess, sys, tempfile, time, uuid, zlib
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA="dev.xenoid.proxy-engine/v1"; IPC_SCHEMA="dev.xenoid.proxy-engine.ipc/v1"
OWNER_SCHEMA="dev.xenoid.proxy-engine.ownership/v1"; CONTROL_SCHEMA="dev.xenoid.proxy-engine.control/v1"
ASSET_URL="https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-linux-arm64-v1.19.29.gz"
ASSET_SHA="9a868b5e4e0ad91d9d71e1b41b0cfce78aaba44360c30df74a723f8e3926a86c"
ASSET_MEMBER=b"mihomo-linux-arm64"; BINARY_SHA="8e02308f672e89c076bfc2fa1b03379bd54e58b0bafa81ffb01113fcf6da348d"; BINARY=Path("/usr/lib/xenoid/proxy/mihomo-v1.19.29")
SANDBOX=Path("/usr/libexec/xenoid-proxy-sandbox"); AGENT_SERVICE=Path("/etc/systemd/system/xenoid-proxy-agent@.service")
ENGINE_HELPER=Path("/usr/libexec/xenoid-proxy-engine.py"); PYTHON_ROOT=Path("/usr/lib/xenoid-proxy/python")
STATE=Path("/var/lib/xenoid/proxy/instances"); RUN=Path("/run/xenoid/proxy")
ASSETS=Path("/var/lib/xenoid/proxy/assets"); ASSET_RECORD=ASSETS/"mihomo-v1.19.29.json"; CONTROL_RECORD=ASSETS/"control-v1.json"
LOCK=Path("/run/xenoid/proxy-engine.lock"); MAX_CONFIG=10*1024*1024; MAX_ARCHIVE=64*1024*1024; MAX_BINARY=256*1024*1024
HEX64=re.compile(r"^[0-9a-f]{64}$"); TOKEN=re.compile(r"^[A-Za-z0-9._-]{16,128}$")
MAC=re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"); SECRET=re.compile(r"^[A-Za-z0-9_-]{32,256}$"); _CONTROL=re.compile(r"[\x00-\x1f\x7f]")
_TOOLS:dict[str,str]={};_REQUEST_DEADLINE:float|None=None

class Error(RuntimeError):
 def __init__(self,code:str): self.code=code; super().__init__(code)
class Parser(argparse.ArgumentParser):
 def error(self,_message:str)->None: raise Error("usage_invalid")

def exact(v:Mapping[str,Any],keys:Sequence[str],code="manifest_invalid"):
 if set(v)!=set(keys): raise Error(code)
def string(v:Any,pat=None):
 if not isinstance(v,str) or not v or len(v)>4096 or "\0" in v or (pat and not pat.fullmatch(v)): raise Error("manifest_invalid")
 return v
def integer(v:Any,lo:int,hi:int):
 if isinstance(v,bool) or not isinstance(v,int) or not lo<=v<=hi: raise Error("manifest_invalid")
 return v
def tool_opt(name:str):
 if name in _TOOLS:return _TOOLS[name]
 for d in ("/usr/sbin","/usr/bin","/sbin","/bin"):
  p=Path(d)/name
  if p.is_file() and os.access(p,os.X_OK): _TOOLS[name]=str(p); return str(p)
 return None
def tool(name:str):
 v=tool_opt(name)
 if not v: raise Error("host_dependency_missing")
 return v
def run(argv:Sequence[str],*,data=None,capture=False,capture_error=False,check=True,code="engine_command_failed"):
 if not argv or not all(isinstance(value,str) and "\0" not in value for value in argv):raise Error("internal_contract_error")
 command=list(argv)
 if any(Path(value).name in ("iptables","ip6tables") for value in command):
  for index,value in enumerate(command[:-1]):
   if value=="-w" and command[index+1]=="-t":command.insert(index+1,"5");break
 names={Path(value).name for value in command}
 timeout=600 if names&{"apk","apt-get","dnf","cc","gcc","clang"} else 90 if names&{"curl","systemctl","sysctl"} else 30
 if _REQUEST_DEADLINE is not None:
  remaining=_REQUEST_DEADLINE-time.monotonic()
  if remaining<=0:raise Error(code)
  timeout=min(timeout,max(0.01,remaining))
 try:
  process=subprocess.Popen(command,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,stdout=subprocess.PIPE if capture else subprocess.DEVNULL,stderr=subprocess.PIPE if capture_error else subprocess.DEVNULL,close_fds=True,start_new_session=True,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C","LC_ALL":"C"})
  try:stdout,error_output=process.communicate(data,timeout=timeout)
  except subprocess.TimeoutExpired as exc:
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   process.wait();raise Error(code) from exc
 except OSError as exc:raise Error(code) from exc
 result=subprocess.CompletedProcess(command,process.returncode,stdout if capture else None,error_output if capture_error else None)
 if check and result.returncode:raise Error(code)
 return result

def secure_parents(path:Path):
 if not path.is_absolute():raise Error("unsafe_path")
 p=Path("/")
 for part in path.parts[1:-1]:
  p/=part
  if not p.exists():continue
  s=p.lstat()
  if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode) or s.st_uid or stat.S_IMODE(s.st_mode)&0o022:raise Error("unsafe_path")
def root_file(path:Path,mode=None):
 try:s=path.lstat()
 except OSError as e:raise Error("unsafe_path") from e
 actual=stat.S_IMODE(s.st_mode)
 if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode) or s.st_uid or actual&0o022 or (mode is not None and actual!=mode):raise Error("unsafe_path")
 return s
def mkdir(path:Path,mode:int):
 secure_parents(path/"x")
 try:
  if path.exists():s=path.lstat()
  else:path.mkdir(parents=True,mode=mode);s=path.lstat();os.chown(path,0,0);os.chmod(path,mode)
 except OSError as e:raise Error("state_write_failed") from e
 if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode) or s.st_uid or stat.S_IMODE(s.st_mode)&0o022:raise Error("unsafe_path")
def owned_dir(path:Path,uid:int,gid:int,mode:int):
 secure_parents(path)
 try:
  if not path.exists():path.mkdir(mode=mode);os.chown(path,uid,gid)
  s=path.lstat()
 except OSError as e:raise Error("state_write_failed") from e
 if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode) or (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))!=(uid,gid,mode):raise Error("unsafe_path")
def validate_provider_cache(m,create=False):
 account=pwd.getpwnam(m["users"]["agent"]);cache=m["_state"]/"provider-cache"
 if create:owned_dir(cache,account.pw_uid,account.pw_gid,0o700)
 else:
  try:directory=cache.lstat()
  except OSError as e:raise Error("provider_cache_invalid") from e
  if stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode) or (directory.st_uid,directory.st_gid,stat.S_IMODE(directory.st_mode))!=(account.pw_uid,account.pw_gid,0o700):raise Error("provider_cache_invalid")
 try:entries=list(cache.iterdir())
 except OSError as e:raise Error("provider_cache_invalid") from e
 if len(entries)>8:raise Error("provider_cache_invalid")
 total=0
 for entry in entries:
  try:s=entry.lstat()
  except OSError as e:raise Error("provider_cache_invalid") from e
  total+=s.st_size
  if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size>2*1024*1024 or total>16*1024*1024 or (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))!=(account.pw_uid,account.pw_gid,0o600):raise Error("provider_cache_invalid")
def atomic(path:Path,payload:bytes,mode:int,uid=0,gid=0):
 secure_parents(path);mkdir(path.parent,0o700);fd=-1;tmp=""
 try:
  fd,tmp=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent);os.fchmod(fd,mode);os.fchown(fd,uid,gid)
  with os.fdopen(fd,"wb",closefd=True) as f:fd=-1;f.write(payload);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path);tmp="";d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 except OSError as e:raise Error("state_write_failed") from e
 finally:
  if fd>=0:os.close(fd)
  if tmp:
   try:os.unlink(tmp)
   except OSError:pass
def sha(path:Path,code="binary_digest_mismatch"):
 try:
  s=path.lstat()
  if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode):raise Error(code)
  h=hashlib.sha256()
  with path.open("rb") as f:
   for b in iter(lambda:f.read(1048576),b""):h.update(b)
  return h.hexdigest()
 except OSError as e:raise Error(code) from e
def read_json(path:Path,code):
 s=root_file(path,0o600)
 if s.st_size>1048576:raise Error(code)
 try:v=json.loads(path.read_text())
 except (OSError,json.JSONDecodeError,UnicodeError) as e:raise Error(code) from e
 if not isinstance(v,dict):raise Error(code)
 return v

def tag_for(i):return hashlib.sha256(b"xenoid-instance/v1\0"+i.encode()).hexdigest()[:12]
def ip(v,version):
 t=string(v)
 try:a=ipaddress.ip_address(t)
 except ValueError as e:raise Error("manifest_invalid") from e
 if a.version!=version or str(a)!=t:raise Error("manifest_invalid")
 return t
def manifest_digest(v):
 u=dict(v);u.pop("manifestDigest",None)
 return hashlib.sha256(json.dumps(u,ensure_ascii=True,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def lease_digest(manifest):
 keys=("instanceId","resourceTag","containerId","networkId","bridgeName","proxyNamespace","android","users","veth","routing","engine","paths","daemon")
 return hashlib.sha256(json.dumps({key:manifest[key] for key in keys},ensure_ascii=True,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def load_manifest(value:str):
 path=Path(value);secure_parents(path);s=root_file(path,0o600)
 if not 2<s.st_size<=65536:raise Error("manifest_invalid")
 try:m=json.loads(path.read_text())
 except Exception as e:raise Error("manifest_invalid") from e
 if not isinstance(m,dict):raise Error("manifest_invalid")
 exact(m,("schema","manifestDigest","instanceId","resourceTag","runtimeEpoch","generation","containerId","networkId","bridgeName","proxyNamespace","android","users","veth","routing","engine","paths","daemon"))
 if m["schema"]!=SCHEMA or string(m["manifestDigest"],HEX64)!=manifest_digest(m):raise Error("manifest_digest_mismatch")
 try:u=uuid.UUID(string(m["instanceId"]))
 except ValueError as e:raise Error("manifest_invalid") from e
 iid=str(u)
 if u.version!=4 or iid!=m["instanceId"]:raise Error("manifest_invalid")
 tag=string(m["resourceTag"],re.compile(r"^[0-9a-f]{12}$"))
 if tag!=tag_for(iid):raise Error("instance_tag_collision")
 string(m["runtimeEpoch"],TOKEN);integer(m["generation"],0,(1<<63)-1);string(m["containerId"],HEX64);string(m["networkId"],HEX64)
 if m["bridgeName"]!=f"xbr{tag}" or m["proxyNamespace"]!=f"xenoid-p-{tag}":raise Error("manifest_resource_mismatch")
 a,us,v,r,e,p,d=m["android"],m["users"],m["veth"],m["routing"],m["engine"],m["paths"],m["daemon"]
 if not all(isinstance(x,dict) for x in (a,us,v,r,e,p,d)):raise Error("manifest_invalid")
 exact(a,("ipv4","ipv6","mac"));exact(us,("proxy","fetcher","compiler","agent"));exact(v,("host","proxy","hostIpv4","proxyIpv4","hostIpv6","proxyIpv6"));exact(r,("mark","mask","tables","rulePriorities"));exact(e,("binaryPath","binarySha256"));exact(p,("config","state","key"));exact(d,("ip","port","adbPort"))
 if us!={"proxy":f"xpm{tag}","fetcher":f"xpf{tag}","compiler":f"xpc{tag}","agent":f"xpa{tag}"} or v["host"]!=f"xph{tag}" or v["proxy"]!=f"xpp{tag}":raise Error("manifest_resource_mismatch")
 mark,mask=integer(r["mark"],0,0xffffffff),integer(r["mask"],0,0xffffffff);slot=(mark^0xa0000000)>>8
 if mask!=0xffffff00 or mark!=(0xa0000000|slot<<8) or not 0<=slot<1000:raise Error("manifest_resource_mismatch")
 if r["tables"]!=[20000+slot*4+x for x in range(4)] or r["rulePriorities"]!=[30000+slot*4+x for x in range(4)]:raise Error("manifest_resource_mismatch")
 actual=(ip(a["ipv4"],4),ip(a["ipv6"],6),ip(v["hostIpv4"],4),ip(v["proxyIpv4"],4),ip(v["hostIpv6"],6),ip(v["proxyIpv6"],6))
 expected=(str(ipaddress.ip_address(int(ipaddress.ip_address("172.31.0.0"))+slot*16+10)),str(ipaddress.ip_address(f"fd78:656e:6f69:{slot:x}::10")),str(ipaddress.ip_address(int(ipaddress.ip_address("169.254.0.0"))+slot*4+1)),str(ipaddress.ip_address(int(ipaddress.ip_address("169.254.0.0"))+slot*4+2)),str(ipaddress.ip_address(f"fd78:7072:6f78:{slot:x}::1")),str(ipaddress.ip_address(f"fd78:7072:6f78:{slot:x}::2")))
 state=STATE/iid
 if actual!=expected or not MAC.fullmatch(a["mac"]) or e!={"binaryPath":str(BINARY),"binarySha256":BINARY_SHA} or p!={"config":str(state/"config.yaml"),"state":str(state),"key":str(state/"agent.key")} or d!={"ip":a["ipv4"],"port":18765,"adbPort":62111}:raise Error("manifest_resource_mismatch")
 if path.parent not in (RUN/tag,state):raise Error("unsafe_manifest")
 m.update(_path=path,_state=state,_slot=slot);return m
def labels_ok(value,m):
 return isinstance(value,dict) and all(value.get(key)==expected for key,expected in (("dev.xenoid.owner","xenoid"),("dev.xenoid.schema","1"),("dev.xenoid.instance_id",m["instanceId"]),("dev.xenoid.resource_tag",m["resourceTag"])))
def runtime_inspect(m,allow_absent=False,allow_stopped=False):
 docker=tool("docker");container=run([docker,"inspect","--type","container",m["containerId"]],capture=True,check=False);network=run([docker,"network","inspect",m["networkId"]],capture=True,check=False);exists=container.returncode==0;network_exists=network.returncode==0
 if exists and not network_exists:raise Error("runtime_identity_mismatch")
 if not exists and not allow_absent:raise Error("runtime_identity_mismatch")
 slot=m["_slot"];gateway4=str(ipaddress.ip_address(int(ipaddress.ip_address("172.31.0.0"))+slot*16+1));gateway6=str(ipaddress.ip_address(f"fd78:656e:6f69:{slot:x}::1"))
 subnet4=str(ipaddress.ip_network(f"{gateway4}/28",strict=False));subnet6=str(ipaddress.ip_network(f"{gateway6}/64",strict=False))
 if network_exists:
  try:network_data=json.loads(network.stdout)[0]
  except Exception as exc:raise Error("runtime_identity_mismatch") from exc
  ipam=network_data.get("IPAM",{}).get("Config")
  actual_ipam={(entry.get("Subnet"),entry.get("Gateway")) for entry in ipam} if isinstance(ipam,list) and all(isinstance(entry,dict) for entry in ipam) else set()
  if network_data.get("Id")!=m["networkId"] or network_data.get("Driver")!="bridge" or network_data.get("Internal") is not False or not labels_ok(network_data.get("Labels"),m) or network_data.get("Options",{}).get("com.docker.network.bridge.name")!=m["bridgeName"] or actual_ipam!={(subnet4,gateway4),(subnet6,gateway6)}:raise Error("runtime_identity_mismatch")
 if not exists:return None
 try:container_data=json.loads(container.stdout)[0]
 except Exception as exc:raise Error("runtime_identity_mismatch") from exc
 networks=container_data.get("NetworkSettings",{}).get("Networks",{});android=m["android"]
 if not isinstance(networks,dict) or len(networks)!=1:raise Error("runtime_identity_mismatch")
 endpoint=next(iter(networks.values()));running=container_data.get("State",{}).get("Running") is True
 if not isinstance(endpoint,dict) or container_data.get("Id")!=m["containerId"] or not labels_ok(container_data.get("Config",{}).get("Labels"),m):raise Error("runtime_identity_mismatch")
 if running:
  if endpoint.get("NetworkID")!=m["networkId"] or (endpoint.get("IPAddress"),endpoint.get("GlobalIPv6Address"),endpoint.get("MacAddress"),endpoint.get("Gateway"),endpoint.get("IPv6Gateway"))!=(android["ipv4"],android["ipv6"],android["mac"],gateway4,gateway6):raise Error("runtime_identity_mismatch")
 elif allow_stopped:
  configured=endpoint.get("IPAMConfig")
  if container_data.get("HostConfig",{}).get("NetworkMode")!=network_data.get("Name") or not isinstance(configured,dict) or (configured.get("IPv4Address"),configured.get("IPv6Address"),endpoint.get("MacAddress"))!=(android["ipv4"],android["ipv6"],android["mac"]) or endpoint.get("NetworkID") not in ("",m["networkId"]):raise Error("runtime_identity_mismatch")
 else:raise Error("runtime_identity_mismatch")
 return container_data
def live(m,allow_absent=False,allow_stopped=False):return runtime_inspect(m,allow_absent,allow_stopped) is not None

def owner_path(m):return m["_state"]/"engine-ownership.json"
def save_owner(m,o):atomic(owner_path(m),json.dumps(o,sort_keys=True,separators=(",",":")).encode()+b"\n",0o600)
def owned_path(m,value):
 path=Path(value)
 if not path.is_absolute() or ".." in path.parts:return False
 roots=(m["_state"],RUN/m["resourceTag"])
 return any(path==root or root in path.parents for root in roots)
def validate_resource(m,resource):
 if not isinstance(resource,dict) or resource.get("kind") not in ("command","file","tree"):raise Error("ownership_invalid")
 kind=resource["kind"]
 if kind=="file":
  exact(resource,("kind","path","sha256"),"ownership_invalid")
  if not owned_path(m,resource["path"]) or not HEX64.fullmatch(string(resource["sha256"])):raise Error("ownership_invalid")
  return
 if kind=="tree":
  exact(resource,("kind","path","uid","gid"),"ownership_invalid")
  if not owned_path(m,resource["path"]) or not all(isinstance(resource[key],int) and resource[key]>0 for key in ("uid","gid")):raise Error("ownership_invalid")
  return
 exact(resource,("kind","delete","scope","state"),"ownership_invalid");command=resource["delete"]
 if resource["scope"] not in ("baseline","transient","epoch-temporary") or resource["state"] not in ("pending","committed"):raise Error("ownership_invalid")
 if not isinstance(command,list) or not 2<=len(command)<=64 or any(not isinstance(arg,str) or not arg or len(arg)>256 or _CONTROL.search(arg) for arg in command):raise Error("ownership_invalid")
 executable=Path(command[0]).name
 if executable not in ("ip","iptables","ip6tables","nsenter"):raise Error("ownership_invalid")
 joined="\0".join(command)
 owned_tokens=(m["resourceTag"],m["proxyNamespace"],m["veth"]["host"],m["veth"]["proxy"],*(str(value) for value in m["routing"]["tables"]),*(str(value) for value in m["routing"]["rulePriorities"]))
 if not any(token in joined for token in owned_tokens):raise Error("ownership_invalid")
 if executable in ("iptables","ip6tables") and not any(flag in command for flag in ("-D","-X")):raise Error("ownership_invalid")
 if executable=="nsenter" and not (len(command)>3 and command[1:3]==[f"--net=/run/netns/{m['proxyNamespace']}","--"] and Path(command[3]).name in ("ip","iptables","ip6tables")):raise Error("ownership_invalid")
def validate_owner(m,o):
 if not isinstance(o["resources"],list) or len(o["resources"])>2048:raise Error("ownership_invalid")
 for resource in o["resources"]:validate_resource(m,resource)
 for field in ("candidate","previous"):
  value=o[field]
  if value is None:continue
  if not isinstance(value,dict):raise Error("ownership_invalid")
  required=("generation","name","path","sha256") if field=="candidate" else ("generation","name")
  exact(value,required,"ownership_invalid")
  integer(value["generation"],0,(1<<63)-1)
  if value["name"] not in ("a","b"):raise Error("ownership_invalid")
  if field=="candidate" and (not owned_path(m,value["path"]) or not HEX64.fullmatch(string(value["sha256"]))):raise Error("ownership_invalid")
def owner(m,create=True):
 mkdir(STATE,0o711);mkdir(m["_state"],0o700);p=owner_path(m)
 if not p.exists():
  if not create:raise Error("engine_not_prepared")
  o={"schema":OWNER_SCHEMA,"instanceId":m["instanceId"],"resourceTag":m["resourceTag"],"runtimeEpoch":m["runtimeEpoch"],"manifestDigest":m["manifestDigest"],"leaseDigest":lease_digest(m),"manifestGeneration":m["generation"],"appliedGeneration":None,"phase":"new","activeCandidate":None,"candidate":None,"previous":None,"binarySha256":m["engine"]["binarySha256"],"pythonPath":str(Path(sys.executable).resolve()),"resources":[]};save_owner(m,o);return o
 o=read_json(p,"ownership_invalid")
 exact(o,("schema","instanceId","resourceTag","runtimeEpoch","manifestDigest","leaseDigest","manifestGeneration","appliedGeneration","phase","activeCandidate","candidate","previous","binarySha256","pythonPath","resources"),"ownership_invalid")
 validate_owner(m,o)
 if o["schema"]!=OWNER_SCHEMA or any(o[k]!=m[k] for k in ("instanceId","resourceTag")) or o["leaseDigest"]!=lease_digest(m) or o["pythonPath"]!=str(Path(sys.executable).resolve()) or o["binarySha256"]!=m["engine"]["binarySha256"]:raise Error("ownership_mismatch")
 if o["runtimeEpoch"]!=m["runtimeEpoch"]:
  if not create:raise Error("ownership_mismatch")
  return rotate_owner(m,o)
 if create and any(resource.get("scope")=="epoch-temporary" for resource in o["resources"]):recover_epoch_transaction(m,o)
 if m["generation"]<o["manifestGeneration"]:raise Error("generation_stale")
 if not create and (m["generation"]!=o["manifestGeneration"] or m["manifestDigest"]!=o["manifestDigest"]):raise Error("ownership_mismatch")
 if create:o["manifestGeneration"],o["manifestDigest"]=m["generation"],m["manifestDigest"];save_owner(m,o)
 return o
def remember(m,o,r):
 if r not in o["resources"]:o["resources"].append(r);save_owner(m,o)
def command_resource(o,delete,scope):
 return next((resource for resource in o["resources"] if resource.get("kind")=="command" and resource.get("delete")==delete and resource.get("scope")==scope),None)
def mutate(m,o,create,delete,code,scope="transient"):
 resource=command_resource(o,delete,scope)
 if resource is None:
  resource={"kind":"command","delete":delete,"scope":scope,"state":"pending"};remember(m,o,resource)
 elif resource["state"]=="committed":
  resource["state"]="pending";save_owner(m,o)
 try:run(create,code=code)
 except Error:raise
 resource["state"]="committed";save_owner(m,o)

def ensure_user(name,home):
 try:a=pwd.getpwnam(name)
 except KeyError:
  shell="/sbin/nologin" if Path("/sbin/nologin").exists() else "/usr/sbin/nologin";run([tool("useradd"),"--system","--no-create-home","--home-dir",str(home),"--shell",shell,"--user-group",name],code="user_setup_failed");a=pwd.getpwnam(name)
 g=grp.getgrnam(name)
 if not a.pw_uid or a.pw_gid!=g.gr_gid or a.pw_dir!=str(home):raise Error("user_identity_mismatch")
 return a.pw_uid,a.pw_gid
def validate_accounts(m,create=False):
 accounts=[]
 for role,name in m["users"].items():
  if create:ensure_user(name,m["_state"])
  try:account=pwd.getpwnam(name);group=grp.getgrnam(name)
  except KeyError as exc:raise Error("user_identity_mismatch") from exc
  nologin=("/sbin/nologin","/usr/sbin/nologin")
  if account.pw_uid<=0 or account.pw_gid<=0 or account.pw_gid!=group.gr_gid or account.pw_dir!=str(m["_state"]) or account.pw_shell not in nologin:raise Error("user_identity_mismatch")
  if any(name in candidate.gr_mem for candidate in grp.getgrall()):raise Error("user_identity_mismatch")
  accounts.append((account.pw_uid,account.pw_gid))
 if len({uid for uid,_ in accounts})!=4 or len({gid for _,gid in accounts})!=4:raise Error("user_identity_mismatch")
def prerequisites():
 if platform.machine().lower() not in ("arm64","aarch64"):raise Error("engine_arch_unsupported")
 for executable in ("ip","iptables","ip6tables","iptables-restore","ip6tables-restore","conntrack","docker","ss","curl","setpriv","sysctl","nsenter","unshare"):tool(executable)
 for relative,expected,code in (("net/ipv4/ip_forward","1","tproxy_unsupported"),("net/ipv6/conf/all/disable_ipv6","0","ipv6_unsupported"),("net/ipv6/conf/all/forwarding","1","ipv6_unsupported"),("net/bridge/bridge-nf-call-iptables","1","tproxy_unsupported"),("net/bridge/bridge-nf-call-ip6tables","1","ipv6_unsupported"),("net/ipv4/conf/all/src_valid_mark","1","rp_filter_unsupported")):
  try:
   if (Path("/proc/sys")/relative).read_text().strip()!=expected:raise Error(code)
  except OSError as exc:raise Error(code) from exc
 try:
  targets4=Path("/proc/net/ip_tables_targets").read_text().split();matches4=Path("/proc/net/ip_tables_matches").read_text().split();targets6=Path("/proc/net/ip6_tables_targets").read_text().split();matches6=Path("/proc/net/ip6_tables_matches").read_text().split()
 except OSError as exc:raise Error("tproxy_unsupported") from exc
 if "TPROXY" not in targets4 or "REDIRECT" not in targets4 or "socket" not in matches4:raise Error("tproxy_unsupported")
 if "TPROXY" not in targets6 or "REDIRECT" not in targets6 or "socket" not in matches6:raise Error("ipv6_unsupported")
def install_deps():
 if tool_opt("apk"):run([tool("apk"),"add","--no-cache","python3","py3-cryptography","py3-yaml","iproute2","iptables","util-linux","libcap","ca-certificates","curl","conntrack-tools","shadow","build-base","procps"],code="dependency_install_failed")
 elif tool_opt("apt-get"):run([tool("apt-get"),"update"],code="dependency_install_failed");run([tool("apt-get"),"install","-y","--no-install-recommends","python3","python3-cryptography","python3-yaml","iproute2","iptables","util-linux","libcap2-bin","ca-certificates","curl","conntrack","gcc","libc6-dev","procps"],code="dependency_install_failed")
 elif tool_opt("dnf"):run([tool("dnf"),"install","-y","python3","python3-cryptography","python3-pyyaml","iproute","iptables","util-linux","libcap","ca-certificates","curl","conntrack-tools","shadow-utils","gcc","glibc-devel","procps-ng"],code="dependency_install_failed")
 else:raise Error("package_manager_unsupported")
def install_prerequisites():
 modprobe=tool_opt("modprobe")
 required_modules=("br_netfilter","xt_TPROXY","xt_socket","xt_REDIRECT","nft_redir","xt_mac","xt_hl","xt_conntrack","xt_addrtype","xt_comment","xt_mark","xt_connmark","xt_owner")
 if modprobe:
  for module in (*required_modules,"nf_tproxy_ipv4","nf_tproxy_ipv6"):run([modprobe,module],check=False)
  atomic(Path("/etc/modules-load.d/99-xenoid-proxy.conf"),("\n".join(required_modules)+"\n").encode("ascii"),0o644)
 settings=b"net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.disable_ipv6 = 0\nnet.ipv6.conf.all.forwarding = 1\nnet.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\nnet.ipv4.conf.all.src_valid_mark = 1\n"
 atomic(Path("/etc/sysctl.d/99-xenoid-proxy.conf"),settings,0o644);run([tool("sysctl"),"--system"],code="tproxy_unsupported");prerequisites()
def parse_gzip(b):
 if len(b)<20 or b[:3]!=b"\x1f\x8b\x08" or b[3]&0xe0:raise Error("engine_download_failed")
 flags,pos=b[3],10
 if flags&4:
  if pos+2>len(b):raise Error("engine_download_failed")
  extra_length=struct.unpack_from("<H",b,pos)[0];pos+=2+extra_length
  if pos>len(b):raise Error("engine_download_failed")
 member=None
 if flags&8:
  end=b.find(b"\0",pos,min(len(b),pos+512))
  if end<0:raise Error("engine_download_failed")
  member=b[pos:end];pos=end+1
 if flags&16:
  end=b.find(b"\0",pos,min(len(b),pos+1024))
  if end<0:raise Error("engine_download_failed")
  pos=end+1
 if flags&2:
  if pos+2>len(b) or (binascii.crc32(b[:pos])&0xffff)!=struct.unpack_from("<H",b,pos)[0]:raise Error("engine_download_failed")
  pos+=2
 if member!=ASSET_MEMBER or b"/" in member or b"\\" in member:raise Error("engine_download_failed")
 d=zlib.decompressobj(-zlib.MAX_WBITS)
 try:binary=d.decompress(b[pos:],MAX_BINARY+1)
 except zlib.error as e:raise Error("engine_download_failed") from e
 footer=pos+len(b[pos:])-len(d.unused_data)
 if len(binary)>MAX_BINARY or not d.eof or footer+8!=len(b):raise Error("engine_download_failed")
 crc,size=struct.unpack_from("<II",b,footer)
 if crc!=(binascii.crc32(binary)&0xffffffff) or size!=(len(binary)&0xffffffff) or binary[:6]!=b"\x7fELF\x02\x01" or struct.unpack_from("<H",binary,18)[0]!=183:raise Error("engine_download_failed")
 return binary
def systemd():
 s=tool_opt("systemctl")
 return bool(s and run([s,"is-system-running"],capture=True,check=False).stdout.decode().strip() in ("running","degraded","starting"))
def require_systemd():
 if not systemd():raise Error("systemd_unavailable")
def install_file(src,dst,mode):
 s=src.lstat()
 if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode):raise Error("install_artifact_missing")
 atomic(dst,src.read_bytes(),mode)
def bounded_fd(fd,limit,code):
 chunks=[];total=0
 while True:
  chunk=os.read(fd,min(1048576,limit+1-total))
  if not chunk:break
  chunks.append(chunk);total+=len(chunk)
  if total>limit:raise Error(code)
 return b"".join(chunks)
def static_aarch64_elf(data):
 if len(data)<64 or data[:6]!=b"\x7fELF\x02\x01" or struct.unpack_from("<H",data,18)[0]!=183:return False
 program_offset=struct.unpack_from("<Q",data,32)[0];entry_size=struct.unpack_from("<H",data,54)[0];entry_count=struct.unpack_from("<H",data,56)[0]
 if entry_size<56 or entry_count>256 or program_offset+entry_size*entry_count>len(data):return False
 return all(struct.unpack_from("<I",data,program_offset+entry_size*index)[0]!=3 for index in range(entry_count))
def install_sandbox(m):
 root=Path(__file__).resolve().parent
 prebuilt=next((path for path in (root/"xenoid-proxy-sandbox",Path("/usr/libexec/xenoid-proxy-sandbox.staged")) if path.is_file()),None)
 if prebuilt is not None:
  data=prebuilt.read_bytes()
  if not static_aarch64_elf(data):raise Error("install_artifact_missing")
  atomic(SANDBOX,data,0o555);return
 source=next((path for path in (root.parent/"native/xenoid-proxy-sandbox"/"xenoid_proxy_sandbox.c",Path("/usr/share/xenoid/proxy/xenoid_proxy_sandbox.c")) if path.is_file()),None)
 if source is None:raise Error("install_artifact_missing")
 compiler=tool_opt("cc") or tool_opt("gcc")
 if compiler is None:raise Error("dependency_install_failed")
 uid,gid=ensure_user(m["users"]["compiler"],m["_state"]);build=m["_state"]/"sandbox-build";owned_dir(build,uid,gid,0o700);output=build/"xenoid-proxy-sandbox"
 run([tool("setpriv"),"--reuid",str(uid),"--regid",str(gid),"--init-groups","--no-new-privs","--bounding-set=-all",compiler,"-O2","-std=c11","-Wall","-Wextra","-Werror","-D_FORTIFY_SOURCE=3","-fstack-protector-strong","-fPIE","-static-pie","-Wl,-z,relro,-z,now","-Wl,-z,noexecstack",str(source),"-o",str(output)],code="sandbox_build_failed")
 data=output.read_bytes()
 if not static_aarch64_elf(data):raise Error("sandbox_build_failed")
 atomic(SANDBOX,data,0o555);output.unlink();build.rmdir()
def control_paths():
 package=PYTHON_ROOT/"xenoid"
 return {ENGINE_HELPER:0o555,AGENT_SERVICE:0o644,SANDBOX:0o555,Path("/usr/libexec/xenoid-proxy-agent.py"):0o555,Path("/usr/libexec/xenoid-proxy-compile-worker.py"):0o555,Path("/usr/libexec/xenoid-proxy-fetch-worker.py"):0o555,package/"__init__.py":0o444,package/"proxy_source.py":0o444,package/"proxy_protocol.py":0o444}
def control_digest(files):return hashlib.sha256(json.dumps(files,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def install_control(m):
 require_systemd();install_deps();install_prerequisites();validate_accounts(m,True);mkdir(ASSETS,0o711);install_sandbox(m)
 root=Path(__file__).resolve().parent;install_file(root/"xenoid-proxy-engine.py",ENGINE_HELPER,0o555);install_file(root/"xenoid-proxy-agent@.service",AGENT_SERVICE,0o644)
 for source_name in ("xenoid-proxy-agent.py","xenoid-proxy-compile-worker.py","xenoid-proxy-fetch-worker.py"):install_file(root/source_name,Path("/usr/libexec")/source_name,0o555)
 package=PYTHON_ROOT/"xenoid";mkdir(package,0o755)
 for source_name in ("__init__.py","proxy_source.py","proxy_protocol.py"):install_file(root/"xenoid"/source_name,package/source_name,0o444)
 paths=control_paths();files={str(path):sha(path) for path in paths};atomic(CONTROL_RECORD,json.dumps({"schema":CONTROL_SCHEMA,"controlDigest":control_digest(files),"files":files},sort_keys=True,separators=(",",":")).encode()+b"\n",0o600)
 if systemd():run([tool("systemctl"),"daemon-reload"],code="systemd_failed")
def install_asset(m):
 validate_control();validate_accounts(m);mkdir(ASSETS,0o711);valid_asset=False
 try:validate_binary(m);valid_asset=True
 except Error:valid_asset=False
 if not valid_asset:
  staged=runtime_dir(m)/"mihomo-v1.19.29.gz";asset=None;fetch_uid,fetch_gid=ensure_user(m["users"]["fetcher"],m["_state"]);expected_uid=0
  try:
   staged_stat=staged.lstat()
  except FileNotFoundError:
   staged_stat=None
  if staged_stat is not None:
   if stat.S_ISLNK(staged_stat.st_mode) or not stat.S_ISREG(staged_stat.st_mode) or staged_stat.st_nlink!=1 or (staged_stat.st_uid,staged_stat.st_gid,stat.S_IMODE(staged_stat.st_mode))!=(0,0,0o600):raise Error("engine_download_failed")
   asset=staged
  else:
   fd,name=tempfile.mkstemp(prefix="asset.",dir=ASSETS);expected_uid=fetch_uid;os.fchmod(fd,0o600);os.fchown(fd,fetch_uid,fetch_gid);os.close(fd);asset=Path(name)
  try:
   if staged_stat is None:
    run([tool("setpriv"),"--reuid",str(fetch_uid),"--regid",str(fetch_gid),"--init-groups","--no-new-privs","--bounding-set=-all",tool("curl"),"--fail","--silent","--location","--connect-timeout","10","--max-time","60","--speed-time","15","--speed-limit","1024","--max-redirs","5","--proto","=https","--proto-redir","=https","--max-filesize",str(MAX_ARCHIVE),"--output",str(asset),ASSET_URL],code="engine_download_failed")
   archive_fd=os.open(asset,os.O_RDONLY|os.O_NOFOLLOW)
   try:archive_stat=os.fstat(archive_fd);data=bounded_fd(archive_fd,MAX_ARCHIVE,"engine_download_failed")
   finally:os.close(archive_fd)
   if archive_stat.st_uid!=expected_uid or not stat.S_ISREG(archive_stat.st_mode) or archive_stat.st_nlink!=1 or len(data)!=archive_stat.st_size or hashlib.sha256(data).hexdigest()!=ASSET_SHA:raise Error("engine_download_failed")
   binary=parse_gzip(data)
   if hashlib.sha256(binary).hexdigest()!=BINARY_SHA:raise Error("engine_download_failed")
   mkdir(BINARY.parent,0o755);atomic(BINARY,binary,0o555)
   version=run([tool("setpriv"),"--reuid",str(fetch_uid),"--regid",str(fetch_gid),"--init-groups","--no-new-privs","--bounding-set=-all",str(BINARY),"-v"],capture=True,code="engine_download_failed").stdout.decode("ascii","strict")
   if not re.search(r"\bv1\.19\.29\b",version) or not re.search(r"\blinux\b",version,re.I) or not re.search(r"\b(?:arm64|aarch64)\b",version,re.I):raise Error("engine_download_failed")
   atomic(ASSET_RECORD,json.dumps({"binaryPath":str(BINARY),"binarySha256":BINARY_SHA,"compressedSha256":ASSET_SHA,"pythonPath":str(Path(sys.executable).resolve()),"sandboxSha256":sha(SANDBOX)},sort_keys=True,separators=(",",":")).encode()+b"\n",0o600)
  finally:
   try:asset.unlink()
   except OSError:pass
def validate_control():
 paths=control_paths();record=read_json(CONTROL_RECORD,"install_artifact_invalid")
 if set(record)!={"schema","controlDigest","files"} or record["schema"]!=CONTROL_SCHEMA or not isinstance(record["files"],dict) or set(record["files"])!={str(path) for path in paths} or record["controlDigest"]!=control_digest(record["files"]):raise Error("install_artifact_invalid")
 for path,mode in paths.items():
  root_file(path,mode)
  if record["files"].get(str(path))!=sha(path):raise Error("install_artifact_invalid")
 return record["controlDigest"]
def check_control(m):
 require_systemd();prerequisites();validate_accounts(m);return validate_control()
def validate_binary(m):
 record=read_json(ASSET_RECORD,"binary_digest_mismatch")
 if record.get("binarySha256")!=BINARY_SHA or m["engine"]["binarySha256"]!=BINARY_SHA or record.get("compressedSha256")!=ASSET_SHA or record.get("pythonPath")!=str(Path(sys.executable).resolve()) or record.get("sandboxSha256")!=sha(SANDBOX) or sha(BINARY)!=BINARY_SHA:raise Error("binary_digest_mismatch")
 root_file(BINARY,0o555);root_file(SANDBOX,0o555);root_file(AGENT_SERVICE,0o644)

def names(m):
 roles=(("guard","G"),("capture","C"),("rawReturn","RR"),("uplink","U"),("gatewayMark","GM"),("nat","N"),("tproxy","T"),("dns","D"),("output","O"),("mark","M"),("input","I"),("meterIn","MI"),("meterUp","MU"),("meterOut","MO"),("meterDnsIn","DI"),("meterTcpIn","TI"),("meterUdpIn","UI"),("meterDnsUp","DU"),("meterTcpUp","TU"),("meterUdpUp","UU"),("meterDnsOut","DO"),("meterTcpOut","TO"),("meterUdpOut","UO"))
 return {f"{role}{family}":f"XP{family}_{m['resourceTag']}_{label}" for role,label in roles for family in ("4","6")}
def pref(m,exe,inside):return [*netns_command(m["proxyNamespace"]),exe] if inside else [exe]
def _commit_existing(m,o,resource):
 if resource is None:raise Error("resource_conflict")
 if resource["state"]=="pending":resource["state"]="committed";save_owner(m,o)
def chain(m,o,exe,table,n,inside=False,scope="transient"):
 p=pref(m,exe,inside);inv=[*p,"-w","-t",table,"-X",n];resource=command_resource(o,inv,scope)
 if not run([*p,"-w","-t",table,"-S",n],check=False).returncode:_commit_existing(m,o,resource)
 else:mutate(m,o,[*p,"-w","-t",table,"-N",n],inv,"netfilter_failed",scope)
def rule(m,o,exe,table,c,args,insert=False,inside=False,scope="transient"):
 args=list(args)
 if "-m" not in args or "comment" not in args:
  jump=args.index("-j") if "-j" in args else len(args)
  args[jump:jump]=["-m","comment","--comment",f"xenoid-proxy/{m['resourceTag']}/{c}/{m['runtimeEpoch']}/{m['generation']}"]
 p=pref(m,exe,inside);inv=[*p,"-w","-t",table,"-D",c,*args];resource=command_resource(o,inv,scope)
 if not run([*p,"-w","-t",table,"-C",c,*args],check=False).returncode:_commit_existing(m,o,resource)
 else:
  cmd=[*p,"-w","-t",table,"-I" if insert else "-A",c];cmd+=(["1"] if insert else [])+args;mutate(m,o,cmd,inv,"netfilter_failed",scope)
def restore(exe,table,lines,inside=None,manifest=None):
 argv=[tool(exe+"-restore"),"-w","5","--noflush"]
 if inside:argv=[*netns_command(inside),*argv]
 if manifest is not None:
  comment=f"xenoid-proxy/{manifest['resourceTag']}/{manifest['runtimeEpoch']}/{manifest['generation']}";lines=[line.replace(" -j ",f" -m comment --comment {comment} -j ",1) if line.startswith("-A ") and " -j " in line else line for line in lines]
 run(argv,data=(f"*{table}\n"+"\n".join(lines)+"\nCOMMIT\n").encode(),code="netfilter_failed")
def check_rule(exe,table,chain_name,args,comment):
 args=list(args);jump=args.index("-j");args[jump:jump]=["-m","comment","--comment",comment];base=[exe] if isinstance(exe,str) else list(exe)
 if run([*base,"-w","-t",table,"-C",chain_name,*args],check=False).returncode:raise Error("engine_structure_mismatch")
def blocked_destinations(family):
 return ("0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.168.0.0/16","224.0.0.0/4") if family=="4" else ("::/128","::1/128","fc00::/7","fe80::/10","ff00::/8")
def program_baseline(m,drop_all):
 n=names(m)
 for f,exe_name in (("4","iptables"),("6","ip6tables")):
  addr=m["android"]["ipv4" if f=="4" else "ipv6"];g,c,raw_return=n["guard"+f],n["capture"+f],n["rawReturn"+f];capture_rules=[f"-F {c}"];guard_rules=[f"-F {g}"]
  if f=="6":
   capture_rules += [f"-A {c} -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j RETURN",f"-A {c} -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j RETURN"]
   guard_rules += [f"-A {g} -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT",f"-A {g} -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT"]
  for port in (m["daemon"]["port"],m["daemon"]["adbPort"]):
   capture_rules.append(f"-A {c} -s {addr} -p tcp --sport {port} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j RETURN")
   guard_rules.append(f"-A {g} -i {m['bridgeName']} -s {addr} -m mac --mac-source {m['android']['mac']} -p tcp --sport {port} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT")
  capture_rules.append(f"-A {c} ! -s {addr} -j DROP")
  capture_rules += [f"-A {c} -d {network} -j DROP" for network in blocked_destinations(f)]
  capture_rules.append(f"-A {c} -m addrtype --dst-type LOCAL -j DROP")
  if drop_all:capture_rules.append(f"-A {c} -j DROP")
  else:capture_rules.append(f"-A {c} -j RETURN")
  if drop_all:guard_rules.append(f"-A {g} -j DROP")
  else:guard_rules += [f"-A {g} -i {m['bridgeName']} -s {addr} -m mac --mac-source {m['android']['mac']} -j RETURN",f"-A {g} -j DROP"]
  restore(exe_name,"mangle",capture_rules,None,m);restore(exe_name,"filter",guard_rules,None,m);restore(exe_name,"raw",[f"-F {raw_return}",f"-A {raw_return} -j DROP"],None,m)
def ensure_baseline(m,o):
 n=names(m)
 for f,exe in (("4",tool("iptables")),("6",tool("ip6tables"))):
  g,c,raw_return=n["guard"+f],n["capture"+f],n["rawReturn"+f];addr=m["android"]["ipv4" if f=="4" else "ipv6"]
  chain(m,o,exe,"filter",g,scope="baseline");chain(m,o,exe,"mangle",c,scope="baseline");chain(m,o,exe,"raw",raw_return,scope="baseline")
  rule(m,o,exe,"filter","DOCKER-USER",["-i",m["bridgeName"],"-m","mac","--mac-source",m["android"]["mac"],"-j",g],True,scope="baseline")
  rule(m,o,exe,"filter","DOCKER-USER",["-i",m["veth"]["host"],"-d",addr,"-j",g],True,scope="baseline")
  rule(m,o,exe,"mangle","PREROUTING",["-i",m["bridgeName"],"-m","mac","--mac-source",m["android"]["mac"],"-j",c],True,scope="baseline")
  rule(m,o,exe,"raw","PREROUTING",["-i",m["veth"]["host"],"-d",addr,"-j",raw_return],True,scope="baseline")
def quarantine(m,o):
 ensure_baseline(m,o);program_baseline(m,True)
 data=runtime_inspect(m,True,True)
 if data is not None and data.get("State",{}).get("Running") is True:android_ipv6(m,container_netns(m)[0],True)
 latch=m["_state"]/"mustBlock";atomic(latch,json.dumps({"instanceId":m["instanceId"],"runtimeEpoch":m["runtimeEpoch"]},sort_keys=True,separators=(",",":")).encode()+b"\n",0o600);o["phase"]="quarantine";save_owner(m,o)
def netns_command(namespace):
 return [tool("nsenter"),f"--net=/run/netns/{namespace}","--"]
def topology(m,o):
 ipcmd=tool("ip");ns=m["proxyNamespace"];inside=netns_command(ns);h,p=m["veth"]["host"],m["veth"]["proxy"];alias=f"xenoid-proxy/{m['resourceTag']}/{m['runtimeEpoch']}"
 if (Path("/run/netns")/ns).exists():
  host=run([ipcmd,"-d","-json","link","show","dev",h],capture=True,check=False)
  peer=run([*inside,ipcmd,"-d","-json","link","show","dev",p],capture=True,capture_error=True,check=False)
  if host.returncode:raise Error("topology_host_missing")
  if peer.returncode:
   code="topology_permission_denied" if b"Operation not permitted" in peer.stderr else "topology_peer_missing"
   raise Error(code)
  try:valid=json.loads(host.stdout)[0].get("ifalias")==alias and json.loads(peer.stdout)[0].get("ifalias")==alias
  except (json.JSONDecodeError,IndexError,TypeError):valid=False
  if not valid:raise Error("topology_alias_conflict")
 else:
  if not run([ipcmd,"link","show","dev",h],check=False).returncode:raise Error("topology_orphan_conflict")
  mutate(m,o,[ipcmd,"netns","add",ns],[ipcmd,"netns","del",ns],"netns_failed")
  mutate(m,o,[ipcmd,"link","add",h,"type","veth","peer","name",p],[ipcmd,"link","del",h],"netns_failed")
  run([ipcmd,"link","set","dev",h,"alias",alias],code="netns_failed");run([ipcmd,"link","set","dev",p,"netns",ns],code="netns_failed");run([*inside,ipcmd,"link","set","dev",p,"alias",alias],code="netns_failed")
 for fam,ha,pa,pre in (("-4",m["veth"]["hostIpv4"],m["veth"]["proxyIpv4"],"30"),("-6",m["veth"]["hostIpv6"],m["veth"]["proxyIpv6"],"126")):
  run([ipcmd,fam,"address","replace",ha+"/"+pre,"dev",h],code="netns_failed");run([*inside,ipcmd,fam,"address","replace",pa+"/"+pre,"dev",p],code="netns_failed")
 run([ipcmd,"link","set",h,"up"],code="netns_failed");run([*inside,ipcmd,"link","set","lo","up"],code="netns_failed");run([*inside,ipcmd,"link","set",p,"up"],code="netns_failed")
 run([*inside,ipcmd,"-4","address","replace","198.18.0.1/32","dev","lo"],code="netns_failed");run([*inside,ipcmd,"-6","address","replace","fd00::1/128","dev","lo"],code="netns_failed")
 for fam,ha,pa,android in (("-4",m["veth"]["hostIpv4"],m["veth"]["proxyIpv4"],m["android"]["ipv4"]),("-6",m["veth"]["hostIpv6"],m["veth"]["proxyIpv6"],m["android"]["ipv6"])):
  run([*inside,ipcmd,fam,"route","replace","default","via",ha,"dev",p],code="netns_failed")
  run([*inside,ipcmd,fam,"route","replace",android,"via",ha,"dev",p],code="netns_failed")
 dual=run([*inside,tool("sysctl"),"-n","net.ipv6.bindv6only"],capture=True,check=False)
 if dual.returncode or dual.stdout.strip()!=b"0":
  run([*inside,tool("sysctl"),"-q","-w","net.ipv6.bindv6only=0"],code="ipv6_unsupported")
  if run([*inside,tool("sysctl"),"-n","net.ipv6.bindv6only"],capture=True,code="ipv6_unsupported").stdout.strip()!=b"0":raise Error("ipv6_unsupported")
 for key in ("net.ipv4.conf.all.rp_filter","net.ipv4.conf.default.rp_filter",f"net.ipv4.conf.{p}.rp_filter"):
  run([*inside,tool("sysctl"),"-q","-w",f"{key}=0"],code="rp_filter_unsupported")
  if run([*inside,tool("sysctl"),"-n",key],capture=True,code="rp_filter_unsupported").stdout.strip()!=b"0":raise Error("rp_filter_unsupported")
 for key in ("net.ipv4.conf.all.src_valid_mark","net.ipv4.conf.default.src_valid_mark",f"net.ipv4.conf.{p}.src_valid_mark"):
  run([*inside,tool("sysctl"),"-q","-w",f"{key}=0"],code="rp_filter_unsupported")
  if run([*inside,tool("sysctl"),"-n",key],capture=True,code="rp_filter_unsupported").stdout.strip()!=b"0":raise Error("rp_filter_unsupported")
 host_mark=Path("/proc/sys/net/ipv4/conf")/h/"src_valid_mark"
 try:valid_mark=host_mark.read_text().strip()
 except OSError as exc:raise Error("rp_filter_unsupported") from exc
 if valid_mark!="1":run([tool("sysctl"),"-q","-w",f"net.ipv4.conf.{h}.src_valid_mark=1"],code="rp_filter_unsupported")
def ensure_policy_rule(m,o,base,fam,priority,mark,table):
 mark_text=f"0x{mark:x}/0x{m['routing']['mask']:x}";output=run([*base,fam,"rule","show"],capture=True,code="policy_route_failed").stdout.decode("ascii","strict")
 occupied=[line for line in output.splitlines() if line.lstrip().startswith(f"{priority}:")]
 add=[*base,fam,"rule","add","priority",str(priority),"fwmark",mark_text,"lookup",str(table)];delete=[*base,fam,"rule","del","priority",str(priority),"fwmark",mark_text,"lookup",str(table)];resource=command_resource(o,delete,"transient")
 if occupied:
  if len(occupied)!=1 or not all(token in occupied[0].split() for token in ("fwmark",mark_text,"lookup",str(table))):raise Error("resource_conflict")
  _commit_existing(m,o,resource)
 else:mutate(m,o,add,delete,"policy_route_failed")
def ensure_route(m,o,base,fam,table,destination,via,device):
 result=run([*base,fam,"route","show","table",str(table)],capture=True,check=False)
 if result.returncode not in (0,2) or (result.returncode and result.stdout):raise Error("policy_route_failed")
 output=result.stdout.decode("ascii","strict")
 normalized=destination
 if "/" in destination:
  network=ipaddress.ip_network(destination,strict=True)
  if network.prefixlen==network.max_prefixlen:normalized=str(network.network_address)
 tokens=(normalized,"dev",device) if via is None else (normalized,"via",via,"dev",device)
 matches=[line for line in output.splitlines() if all(token in line.split() for token in tokens)]
 add=[*base,fam,"route","add","table",str(table),destination,*([] if via is None else ["via",via]),"dev",device];delete=[*base,fam,"route","del","table",str(table),destination,*([] if via is None else ["via",via]),"dev",device];resource=command_resource(o,delete,"transient")
 if matches:
  if len(matches)!=1:raise Error("resource_conflict")
  _commit_existing(m,o,resource)
 else:mutate(m,o,add,delete,"policy_route_failed")
def policy(m,o):
 ipcmd=tool("ip");base=[*netns_command(m["proxyNamespace"]),ipcmd];mask=m["routing"]["mask"]
 for role,capture_index,return_index in ((0x00100000,0,1),(0x00200000,2,3)):
  capture_mark=m["routing"]["mark"]|role;response_mark=capture_mark|0x00010000
  for fam,gateway,android,bits,probe in (("-4",m["veth"]["proxyIpv4"],m["android"]["ipv4"],"32","1.1.1.1"),("-6",m["veth"]["proxyIpv6"],m["android"]["ipv6"],"128","2606:4700:4700::1111")):
   capture_table=m["routing"]["tables"][capture_index];capture_priority=m["routing"]["rulePriorities"][capture_index]
   ensure_route(m,o,[ipcmd],fam,capture_table,"default",gateway,m["veth"]["host"]);ensure_policy_rule(m,o,[ipcmd],fam,capture_priority,capture_mark,capture_table)
   run([*base,fam,"route","replace","table",str(capture_table),"local","default","dev","lo"],code="policy_route_failed");ensure_policy_rule(m,o,base,fam,capture_priority,capture_mark,capture_table)
   return_table=m["routing"]["tables"][return_index];return_priority=m["routing"]["rulePriorities"][return_index];destination=android+"/"+bits
   ensure_route(m,o,[ipcmd],fam,return_table,destination,None,m["bridgeName"]);ensure_route(m,o,[ipcmd],fam,return_table,"default",gateway,m["veth"]["host"]);ensure_policy_rule(m,o,[ipcmd],fam,return_priority,response_mark,return_table)
   route=run([ipcmd,fam,"route","get",probe,"from",gateway,"mark",f"0x{response_mark:x}","iif",m["veth"]["host"]],capture=True,code="rp_filter_unsupported").stdout.decode("ascii","strict").split()
   if "dev" not in route or route[route.index("dev")+1]!=m["veth"]["host"]:raise Error("rp_filter_unsupported")
def dataplane(m,o):
 n=names(m)
 for f,exe in (("4",tool("iptables")),("6",tool("ip6tables"))):
  for role,table in (("uplink","filter"),("gatewayMark","mangle"),("nat","nat"),("meterIn","mangle"),("meterUp","filter"),("meterOut","filter"),("meterDnsIn","mangle"),("meterTcpIn","mangle"),("meterUdpIn","mangle"),("meterDnsOut","filter"),("meterTcpOut","filter"),("meterUdpOut","filter")):chain(m,o,exe,table,n[role+f])
  rule(m,o,exe,"filter","FORWARD",["-i",m["veth"]["host"],"-j",n["uplink"+f]],True);rule(m,o,exe,"filter","FORWARD",["-o",m["veth"]["host"],"-j",n["uplink"+f]],True);rule(m,o,exe,"mangle","PREROUTING",["-i",m["veth"]["host"],"-j",n["gatewayMark"+f]],True);rule(m,o,exe,"nat","POSTROUTING",["-s",m["veth"]["proxyIpv4" if f=="4" else "proxyIpv6"],"-j",n["nat"+f]])
  rule(m,o,exe,"nat","POSTROUTING",["-s",m["android"]["ipv4" if f=="4" else "ipv6"],"-j",n["nat"+f]],True)
  for role,table in (("tproxy","mangle"),("dns","nat"),("output","filter"),("mark","mangle"),("input","filter"),("meterDnsUp","nat"),("meterTcpUp","mangle"),("meterUdpUp","mangle")):chain(m,o,exe,table,n[role+f],True)
  rule(m,o,exe,"mangle","PREROUTING",["-i",m["veth"]["proxy"],"-j",n["tproxy"+f]],True,True);rule(m,o,exe,"nat","PREROUTING",["-i",m["veth"]["proxy"],"-j",n["dns"+f]],True,True);rule(m,o,exe,"filter","OUTPUT",["-m","owner","--uid-owner",m["users"]["proxy"],"-j",n["output"+f]],True,True);rule(m,o,exe,"mangle","OUTPUT",["-m","owner","--uid-owner",m["users"]["proxy"],"-j",n["mark"+f]],True,True);rule(m,o,exe,"filter","INPUT",["-j",n["input"+f]],True,True)
def prepare_runtime(m,o):
 quarantine(m,o);prerequisites();validate_control();validate_accounts(m,True)
 validate_provider_cache(m,True);topology(m,o);policy(m,o);dataplane(m,o);o["phase"]="prepared";save_owner(m,o)
def prepare(m,o):
 prepare_runtime(m,o)
def listener(value,hosts,port):
 return isinstance(value,str) and value in {f"{host}:{port}" for host in hosts}
def validate_config(m,c):
 if not isinstance(c,dict):raise Error("config_invalid")
 top={"mode","log-level","allow-lan","bind-address","find-process-mode","ipv6","hosts","listeners","external-controller","tun","iptables","profile","geo-auto-update","sniffer","dns","proxies","proxy-groups","rules","secret"}
 if set(c)!=top or c["mode"]!="global" or c["log-level"]!="info" or c["allow-lan"] is not True or c["bind-address"]!="*" or c["find-process-mode"]!="off" or c["ipv6"] is not True or c["geo-auto-update"] is not False:raise Error("config_invalid")
 if c["tun"]!={"enable":False} or c["iptables"]!={"enable":False} or c["profile"]!={"store-selected":False,"store-fake-ip":False} or c["rules"]!=["MATCH,GLOBAL"]:raise Error("config_invalid")
 expected_sniffer={"enable":True,"force-dns-mapping":True,"parse-pure-ip":True,"override-destination":True,"sniff":{"HTTP":{"ports":[80,"8080-8880"]},"TLS":{"ports":[443,8443]},"QUIC":{"ports":[443,8443]}}}
 if c["sniffer"]!=expected_sniffer:raise Error("config_invalid")
 listeners=c["listeners"]
 if not isinstance(listeners,list) or len(listeners)!=4 or not all(isinstance(listener,dict) for listener in listeners):raise Error("config_invalid")
 listener_ports=tuple(item.get("port") for item in listeners)
 candidate="a" if listener_ports==(7893,7895,7897,7899) else "b" if listener_ports==(7894,7896,7898,7900) else None
 if candidate is None:raise Error("config_invalid")
 udp_allowed=listeners[2].get("udp")
 if not isinstance(udp_allowed,bool) or listeners[3].get("udp")!=udp_allowed:raise Error("config_invalid")
 expected_listeners=[{"name":"xenoid-redir-v4","type":"redir","port":listener_ports[0],"listen":"0.0.0.0"},{"name":"xenoid-redir-v6","type":"redir","port":listener_ports[1],"listen":"::"},{"name":"xenoid-tproxy-v4","type":"tproxy","port":listener_ports[2],"listen":"0.0.0.0","udp":udp_allowed},{"name":"xenoid-tproxy-v6","type":"tproxy","port":listener_ports[3],"listen":"::","udp":udp_allowed}]
 if listeners!=expected_listeners:raise Error("config_invalid")
 transparent_ports=((listener_ports[0],listener_ports[1]),(listener_ports[2],listener_ports[3]));dns_port,controller_port=(1053,9091) if candidate=="a" else (1054,9092);dns=c["dns"];secret=c["secret"]
 expected_dns={"enable":True,"listen":f"[::]:{dns_port}","enhanced-mode":"redir-host","respect-rules":True,"ipv6":True,"nameserver":["https://8.8.8.8/dns-query#GLOBAL","https://8.8.4.4/dns-query#GLOBAL"],"proxy-server-nameserver":["https://8.8.8.8/dns-query#DIRECT","https://8.8.4.4/dns-query#DIRECT"]}
 if dns!=expected_dns or c["external-controller"]!=f"127.0.0.1:{controller_port}" or not isinstance(secret,str) or not SECRET.fullmatch(secret):raise Error("config_invalid")
 proxy_keys={
  "http":{"name","type","server","port","udp","username","password","tls","sni","skip-cert-verify","fingerprint","alpn"},
  "socks5":{"name","type","server","port","udp","username","password","tls","sni","skip-cert-verify","fingerprint"},
  "ss":{"name","type","server","port","udp","cipher","password","plugin","plugin-opts","udp-over-tcp"},
  "ssr":{"name","type","server","port","udp","cipher","password","protocol","protocol-param","obfs","obfs-param"},
  "trojan":{"name","type","server","port","udp","password","sni","alpn","skip-cert-verify","network","ws-opts","grpc-opts","client-fingerprint"},
  "vmess":{"name","type","server","port","udp","uuid","alterId","cipher","tls","servername","server-name","skip-cert-verify","network","ws-opts","grpc-opts","http-opts","alpn","client-fingerprint","packet-encoding","global-padding","authenticated-length"},
  "vless":{"name","type","server","port","udp","uuid","tls","servername","server-name","flow","skip-cert-verify","network","ws-opts","grpc-opts","reality-opts","alpn","client-fingerprint","packet-encoding"},
  "hysteria":{"name","type","server","port","udp","auth-str","auth","obfs","protocol","up","down","sni","alpn","skip-cert-verify","recv-window-conn","recv-window","disable-mtu-discovery","fast-open"},
  "hysteria2":{"name","type","server","port","udp","password","obfs","obfs-password","sni","fingerprint","alpn","skip-cert-verify","up","down","fast-open","ports","hop-interval"},
  "tuic":{"name","type","server","port","udp","uuid","password","token","ip","congestion-controller","udp-relay-mode","udp-over-stream","reduce-rtt","sni","alpn","disable-sni","skip-cert-verify","heartbeat-interval","request-timeout","max-open-streams"},
  "anytls":{"name","type","server","port","udp","password","client-fingerprint","sni","alpn","skip-cert-verify","idle-session-check-interval","idle-session-timeout","min-idle-session"},
  "mieru":{"name","type","server","port","udp","username","password","transport","multiplexing","handshake-mode","traffic-pattern","mtu"},
  "snell":{"name","type","server","port","udp","psk","version","obfs-opts"},
 }
 def safe_value(value,depth=0):
  if depth>8:raise Error("config_invalid")
  if value is None or isinstance(value,(bool,int,float)):return
  if isinstance(value,str):
   try:value.encode("utf-8")
   except UnicodeEncodeError as exc:raise Error("config_invalid") from exc
   if len(value)>4096 or _CONTROL.search(value):raise Error("config_invalid")
   return
  if isinstance(value,list):
   if len(value)>64:raise Error("config_invalid")
   for item in value:safe_value(item,depth+1)
   return
  if isinstance(value,dict):
   if len(value)>64:raise Error("config_invalid")
   forbidden={"certificate","private-key","private-key-path","interface-name","routing-mark","dialer-proxy"}
   for key,item in value.items():
    try:encoded_key=key.encode("utf-8") if isinstance(key,str) else b""
    except UnicodeEncodeError as exc:raise Error("config_invalid") from exc
    if not isinstance(key,str) or not encoded_key or len(key)>64 or _CONTROL.search(key) or key in forbidden:raise Error("config_invalid")
    safe_value(item,depth+1)
   return
  raise Error("config_invalid")
 proxies=c["proxies"]
 if not isinstance(proxies,list) or not 1<=len(proxies)<=512:raise Error("config_invalid")
 names=[]
 for proxy in proxies:
  if not isinstance(proxy,dict):raise Error("config_invalid")
  kind=proxy.get("type");required={"name","type","server","port","udp"} if kind!="mieru" else {"name","type","server","port","username","password","transport"}
  if kind not in proxy_keys or not required<=set(proxy) or set(proxy)-proxy_keys[kind]:raise Error("config_invalid")
  safe_value(proxy)
  name=proxy["name"]
  if not isinstance(name,str) or not 1<=len(name)<=128 or _CONTROL.search(name) or name in ("GLOBAL","XENOID-AUTO","DIRECT","REJECT","PASS","COMPATIBLE") or name in names:raise Error("config_invalid")
  if not isinstance(proxy["server"],str) or not 1<=len(proxy["server"])<=253 or _CONTROL.search(proxy["server"]) or isinstance(proxy["port"],bool) or not isinstance(proxy["port"],int) or not 1<=proxy["port"]<=65535 or ("udp" in proxy and not isinstance(proxy["udp"],bool)):raise Error("config_invalid")
  if kind=="http" and proxy["udp"] is not False:raise Error("config_invalid")
  if kind=="mieru":
   if not all(isinstance(proxy[field],str) and 1<=len(proxy[field])<=512 and not _CONTROL.search(proxy[field]) for field in ("username","password")) or proxy["transport"] not in ("TCP","UDP"):raise Error("config_invalid")
   if "multiplexing" in proxy and proxy["multiplexing"] not in ("MULTIPLEXING_OFF","MULTIPLEXING_LOW","MULTIPLEXING_MIDDLE","MULTIPLEXING_HIGH"):raise Error("config_invalid")
   if "handshake-mode" in proxy and proxy["handshake-mode"] not in ("HANDSHAKE_STANDARD","HANDSHAKE_NO_WAIT"):raise Error("config_invalid")
   if "traffic-pattern" in proxy and (not isinstance(proxy["traffic-pattern"],str) or len(proxy["traffic-pattern"])>4096 or _CONTROL.search(proxy["traffic-pattern"])):raise Error("config_invalid")
   if "mtu" in proxy and (isinstance(proxy["mtu"],bool) or not isinstance(proxy["mtu"],int) or not 1280<=proxy["mtu"]<=65535):raise Error("config_invalid")
  if proxy["type"]=="ss":
   option_fields={"obfs":{"mode","host"},"obfs-local":{"mode","host"},"v2ray-plugin":{"mode","tls","host","path","mux","headers","skip-cert-verify"},"shadow-tls":{"host","password","version","strict"},"restls":{"host","version-hint","restls-script"}}
   has_plugin="plugin" in proxy
   if has_plugin!=("plugin-opts" in proxy):raise Error("config_invalid")
   if has_plugin and (proxy["plugin"] not in option_fields or not isinstance(proxy["plugin-opts"],dict) or set(proxy["plugin-opts"])-option_fields[proxy["plugin"]]):raise Error("config_invalid")
  names.append(name)
 proxy_hosts=set()
 for proxy in proxies:
  try:ipaddress.ip_address(proxy["server"])
  except ValueError:proxy_hosts.add(proxy["server"])
 hosts=c["hosts"]
 if not isinstance(hosts,dict) or (hosts and set(hosts)!=proxy_hosts):raise Error("config_invalid")
 for hostname,addresses in hosts.items():
  if not isinstance(hostname,str) or hostname not in proxy_hosts or not isinstance(addresses,list) or not 1<=len(addresses)<=16:raise Error("config_invalid")
  for value in addresses:
   try:address=ipaddress.ip_address(value)
   except ValueError as exc:raise Error("config_invalid") from exc
   if str(address)!=value or not address.is_global:raise Error("config_invalid")
 groups=c["proxy-groups"]
 if not isinstance(groups,list) or len(groups)!=2:raise Error("config_invalid")
 auto,global_group=groups
 if auto!={"name":"XENOID-AUTO","type":"url-test","proxies":names,"url":"https://cp.cloudflare.com/generate_204","interval":300,"lazy":True}:raise Error("config_invalid")
 if not isinstance(global_group,dict) or set(global_group)!={"name","type","proxies"} or global_group["name"]!="GLOBAL" or global_group["type"]!="select" or not isinstance(global_group["proxies"],list):raise Error("config_invalid")
 members=global_group["proxies"]
 if len(members)!=len(names)+1 or members.count("XENOID-AUTO")!=1 or members.index("XENOID-AUTO") not in (0,len(members)-1) or set(members)-{"XENOID-AUTO"}!=set(names) or len(set(members))!=len(members):raise Error("config_invalid")
 return candidate,transparent_ports,dns_port,controller_port,secret,udp_allowed
def resolve_proxy_hosts(c):
 servers={}
 for proxy in c["proxies"]:
  server=proxy["server"]
  try:ipaddress.ip_address(server);continue
  except ValueError:servers.setdefault(server,proxy["port"])
 if not servers:return {}
 def resolve(item):
  server,port=item
  try:answers=socket.getaddrinfo(server,port,0,socket.SOCK_STREAM)
  except socket.gaierror as exc:raise Error("proxy_resolution_failed") from exc
  addresses=[]
  for answer in answers:
   try:address=ipaddress.ip_address(answer[4][0])
   except ValueError:continue
   value=str(address)
   if address.is_global and value not in addresses:addresses.append(value)
  if not addresses:raise Error("proxy_resolution_failed")
  return server,addresses[:16]
 executor=concurrent.futures.ThreadPoolExecutor(max_workers=min(32,len(servers)))
 futures={server:executor.submit(resolve,(server,port)) for server,port in servers.items()}
 deadline=time.monotonic()+15
 try:
  resolved={}
  for server in sorted(futures):
   remaining=deadline-time.monotonic()
   if remaining<=0:raise Error("proxy_resolution_failed")
   try:name,addresses=futures[server].result(timeout=remaining)
   except concurrent.futures.TimeoutError as exc:raise Error("proxy_resolution_failed") from exc
   resolved[name]=addresses
  return resolved
 finally:executor.shutdown(wait=False,cancel_futures=True)
def write_config(m,o,payload,expected_generation=None):
 if not payload or len(payload)>MAX_CONFIG or b"\0" in payload:raise Error("config_invalid")
 try:envelope=json.loads(payload)
 except Exception as exc:raise Error("config_invalid") from exc
 if not isinstance(envelope,dict):raise Error("config_invalid")
 exact(envelope,("instanceId","runtimeEpoch","generation","config"),"config_invalid")
 if envelope["instanceId"]!=m["instanceId"] or envelope["runtimeEpoch"]!=m["runtimeEpoch"]:raise Error("runtime_epoch_mismatch")
 generation=integer(envelope["generation"],m["generation"],(1<<63)-1)
 if expected_generation is not None and generation!=expected_generation:raise Error("ipc_request_invalid")
 incoming=envelope["config"];logical,*_=validate_config(m,incoming)
 if incoming["hosts"] or logical!="a":raise Error("config_invalid")
 existing=o.get("candidate")
 if isinstance(existing,dict) and existing.get("generation")==generation:
  path=Path(existing["path"]);root_file(path)
  if sha(path)!=existing["sha256"]:raise Error("config_digest_mismatch")
  try:stored=json.loads(path.read_text())
  except (OSError,json.JSONDecodeError) as exc:raise Error("config_invalid") from exc
  stored_name,*_=validate_config(m,stored);expected=json.loads(json.dumps(incoming,ensure_ascii=True,separators=(",",":")))
  if stored_name=="b":
   for listener in expected["listeners"]:listener["port"]+=1
   expected["external-controller"]="127.0.0.1:9092";expected["dns"]["listen"]="[::]:1054"
  comparable=json.loads(json.dumps(stored,ensure_ascii=True,separators=(",",":")));comparable["hosts"]={}
  if stored_name!=existing["name"] or comparable!=expected:raise Error("generation_stale")
  o["phase"]="configured";save_owner(m,o);return
 candidate="b" if o.get("activeCandidate")=="a" else "a";config=json.loads(json.dumps(incoming,ensure_ascii=True,separators=(",",":")))
 config["hosts"]=resolve_proxy_hosts(config)
 if candidate=="b":
  for listener in config["listeners"]:listener["port"]+=1
  config["external-controller"]="127.0.0.1:9092";config["dns"]["listen"]="[::]:1054"
 validate_config(m,config);data=json.dumps(config,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode("utf-8")+b"\n";digest=hashlib.sha256(data).hexdigest();directory=m["_state"]/"candidates"/str(generation);mkdir(m["_state"]/"candidates",0o700);mkdir(directory,0o750);account=pwd.getpwnam(m["users"]["proxy"]);os.chown(directory,0,account.pw_gid);path=directory/"config.yaml"
 if path.exists():
  metadata=root_file(path,0o640)
  if metadata.st_gid!=account.pw_gid or metadata.st_nlink!=1:raise Error("resource_conflict")
  try:path.unlink()
  except OSError as exc:raise Error("state_write_failed") from exc
 atomic(path,data,0o640,0,account.pw_gid);remember(m,o,{"kind":"file","path":str(path),"sha256":digest});o["candidate"]={"generation":generation,"name":candidate,"path":str(path),"sha256":digest};o["phase"]="configured";save_owner(m,o)
def marks(m,c):
 r=0x00100000 if c=="a" else 0x00200000;b=m["routing"]["mark"];return b|r,b|r|0x00010000,b|r|0x00020000
def configure(m,c,ports,dp,udp_allowed):
 n=names(m);cap,resp,up=marks(m,c);mask=m["routing"]["mask"];tcp_ports,udp_ports=ports
 for f,exe in (("4","iptables"),("6","ip6tables")):
  a=m["android"]["ipv4" if f=="4" else "ipv6"];p=m["veth"]["proxyIpv4" if f=="4" else "proxyIpv6"];index=0 if f=="4" else 1;tcp_port=tcp_ports[index];udp_port=udp_ports[index];t,d,o,mark_chain,input_chain=n["tproxy"+f],n["dns"+f],n["output"+f],n["mark"+f],n["input"+f]
  tcp_up,udp_up,dns_up=n["meterTcpUp"+f],n["meterUdpUp"+f],n["meterDnsUp"+f]
  tproxy_rules=[f"-F {tcp_up}",f"-A {tcp_up} -j RETURN",f"-F {udp_up}",f"-A {udp_up} -j RETURN",f"-F {t}"]
  if f=="6":tproxy_rules += [f"-A {t} -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j RETURN",f"-A {t} -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j RETURN"]
  for proto in ("tcp","udp"):tproxy_rules += [f"-A {t} -s {a} -p {proto} --dport 53 -j MARK --set-xmark 0x{cap:x}/0x{mask:x}",f"-A {t} -s {a} -p {proto} --dport 53 -j RETURN"]
  tproxy_rules += [f"-A {t} -d {p} -p tcp --dport 53 -j MARK --set-xmark 0x{cap:x}/0x{mask:x}",f"-A {t} -d {p} -p udp --dport 53 -j MARK --set-xmark 0x{cap:x}/0x{mask:x}",f"-A {t} -d {p} -j RETURN",f"-A {t} -p tcp -j {tcp_up}",f"-A {t} -p tcp -j MARK --set-xmark 0x0/0x{mask:x}",f"-A {t} -p tcp -j RETURN",f"-A {t} -p udp -j {udp_up}"]
  if udp_allowed:tproxy_rules += [f"-A {t} -p udp -m socket --transparent -j MARK --set-xmark 0x{cap:x}/0x{mask:x}",f"-A {t} -p udp -m socket --transparent -j ACCEPT",f"-A {t} -p udp -j TPROXY --on-port {udp_port} --tproxy-mark 0x{cap:x}/0x{mask:x}",f"-A {t} -p udp -j ACCEPT"]
  else:tproxy_rules += [f"-A {t} -p udp -j DROP"]
  tproxy_rules += [f"-A {t} -j DROP"]
  restore(exe,"mangle",tproxy_rules,m["proxyNamespace"],m)
  restore(exe,"nat",[f"-F {dns_up}",f"-A {dns_up} -j RETURN",f"-F {d}",f"-A {d} -p tcp --dport 53 -j {dns_up}",f"-A {d} -p tcp --dport 53 -j REDIRECT --to-ports {dp}",f"-A {d} -p tcp -j REDIRECT --to-ports {tcp_port}",f"-A {d} -p udp --dport 53 -j {dns_up}",f"-A {d} -p udp --dport 53 -j REDIRECT --to-ports {dp}"],m["proxyNamespace"],m)
  restore(exe,"mangle",[f"-F {mark_chain}",f"-A {mark_chain} -d {a} -j MARK --set-xmark 0x{resp:x}/0x{mask:x}",f"-A {mark_chain} ! -d {a} -j MARK --set-xmark 0x{up:x}/0x{mask:x}"],m["proxyNamespace"],m)
  input_rules=[f"-F {input_chain}",f"-A {input_chain} -i lo -j ACCEPT"]
  if f=="6":input_rules += [f"-A {input_chain} -i {m['veth']['proxy']} -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT",f"-A {input_chain} -i {m['veth']['proxy']} -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT"]
  input_rules += [f"-A {input_chain} -i {m['veth']['proxy']} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",f"-A {input_chain} -i {m['veth']['proxy']} -s {a} -p tcp -j ACCEPT",f"-A {input_chain} -i {m['veth']['proxy']} -s {a} -m mark --mark 0x{cap:x}/0x{mask:x} -p udp -j ACCEPT",f"-A {input_chain} -j DROP"]
  restore(exe,"filter",input_rules,m["proxyNamespace"],m)
  output=[f"-F {o}",f"-A {o} -o lo -j ACCEPT",f"-A {o} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",f"-A {o} -d {a} -m mark --mark 0x{resp:x}/0x{mask:x} -j ACCEPT"]
  output += [f"-A {o} -d {network} -j DROP" for network in blocked_destinations(f)]
  output += [f"-A {o} -o {m['veth']['proxy']} -p tcp -m mark --mark 0x{up:x}/0x{mask:x} -j ACCEPT",f"-A {o} -o {m['veth']['proxy']} -p udp -m mark --mark 0x{up:x}/0x{mask:x} -j ACCEPT",f"-A {o} -j DROP"]
  restore(exe,"filter",output,m["proxyNamespace"],m)
def activate(m,c):
 n=names(m);cap,resp,up=marks(m,c);mask=m["routing"]["mask"]
 for f,exe in (("4","iptables"),("6","ip6tables")):
  a=m["android"]["ipv4" if f=="4" else "ipv6"];p=m["veth"]["proxyIpv4" if f=="4" else "proxyIpv6"];cc,g,raw_return,u,gateway_mark,nat_chain=n["capture"+f],n["guard"+f],n["rawReturn"+f],n["uplink"+f],n["gatewayMark"+f],n["nat"+f];meter_in,meter_up,meter_out=n["meterIn"+f],n["meterUp"+f],n["meterOut"+f]
  dns_in,tcp_in,udp_in=n["meterDnsIn"+f],n["meterTcpIn"+f],n["meterUdpIn"+f];dns_out,tcp_out,udp_out=n["meterDnsOut"+f],n["meterTcpOut"+f],n["meterUdpOut"+f];gateway_rules=[f"-F {gateway_mark}",f"-A {gateway_mark} -d {a} -j MARK --set-xmark 0x{resp:x}/0x{mask:x}",f"-A {gateway_mark} ! -d {a} -j MARK --set-xmark 0x{up:x}/0x{mask:x}"]
  uplink_rules=[f"-F {u}",f"-A {u} -o {m['veth']['host']} -d {p} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",f"-A {u} -i {m['bridgeName']} -o {m['veth']['host']} -s {a} -m mac --mac-source {m['android']['mac']} -m mark --mark 0x{cap:x}/0x{mask:x} -p tcp -j ACCEPT",f"-A {u} -i {m['bridgeName']} -o {m['veth']['host']} -s {a} -m mac --mac-source {m['android']['mac']} -m mark --mark 0x{cap:x}/0x{mask:x} -p udp -j ACCEPT",f"-A {u} -i {m['veth']['host']} -m mark --mark 0x{up:x}/0x{mask:x} -p tcp -j {meter_up}",f"-A {u} -i {m['veth']['host']} -m mark --mark 0x{up:x}/0x{mask:x} -p tcp -j ACCEPT",f"-A {u} -i {m['veth']['host']} -m mark --mark 0x{up:x}/0x{mask:x} -p udp -j {meter_up}",f"-A {u} -i {m['veth']['host']} -m mark --mark 0x{up:x}/0x{mask:x} -p udp -j ACCEPT",f"-A {u} -j DROP"]
  uplink_rules.insert(1,f"-A {u} -i {m['veth']['host']} -o {m['bridgeName']} -d {a} -m mark --mark 0x{resp:x}/0x{mask:x} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN")
  capture=[f"-F {cc}"];guard=[f"-F {g}"]
  if f=="6":
   capture += [f"-A {cc} -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j RETURN",f"-A {cc} -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j RETURN"]
   guard += [f"-A {g} -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT",f"-A {g} -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT"]
  for port in (m["daemon"]["port"],m["daemon"]["adbPort"]):
   capture.append(f"-A {cc} -s {a} -p tcp --sport {port} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j RETURN")
   guard.append(f"-A {g} -i {m['bridgeName']} -s {a} -m mac --mac-source {m['android']['mac']} -p tcp --sport {port} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT")
  capture.append(f"-A {cc} ! -s {a} -j DROP")
  for proto in ("tcp","udp"):
   capture += [f"-A {cc} -p {proto} --dport 53 -j MARK --set-xmark 0x{cap:x}/0x{mask:x}",f"-A {cc} -p {proto} --dport 53 -m mark --mark 0x{cap:x}/0x{mask:x} -j {dns_in}",f"-A {cc} -p {proto} --dport 53 -m mark --mark 0x{cap:x}/0x{mask:x} -j {meter_in}",f"-A {cc} -p {proto} --dport 53 -m mark --mark 0x{cap:x}/0x{mask:x} -j ACCEPT"]
  capture += [f"-A {cc} -d {network} -j DROP" for network in blocked_destinations(f)]
  capture += [f"-A {cc} -m addrtype --dst-type LOCAL -j DROP",f"-A {cc} -p tcp -j MARK --set-xmark 0x{cap:x}/0x{mask:x}",f"-A {cc} -p tcp -j {tcp_in}",f"-A {cc} -p tcp -j {meter_in}",f"-A {cc} -p udp -j MARK --set-xmark 0x{cap:x}/0x{mask:x}",f"-A {cc} -p udp -j {udp_in}",f"-A {cc} -p udp -j {meter_in}",f"-A {cc} -m mark ! --mark 0x{cap:x}/0x{mask:x} -j DROP"]
  guard += [f"-A {g} -i {m['bridgeName']} -o {m['veth']['host']} -s {a} -m mac --mac-source {m['android']['mac']} -m mark --mark 0x{cap:x}/0x{mask:x} -p tcp -j ACCEPT",f"-A {g} -i {m['bridgeName']} -o {m['veth']['host']} -s {a} -m mac --mac-source {m['android']['mac']} -m mark --mark 0x{cap:x}/0x{mask:x} -p udp -j ACCEPT"]
  response=f"-A {g} -i {m['veth']['host']} -o {m['bridgeName']} -d {a} -m mark --mark 0x{resp:x}/0x{mask:x} -m conntrack --ctstate ESTABLISHED,RELATED"
  for proto in ("tcp","udp"):guard += [f"{response} -p {proto} --sport 53 -j {dns_out}",f"{response} -p {proto} --sport 53 -j {meter_out}",f"{response} -p {proto} --sport 53 -j ACCEPT"]
  guard += [f"{response} -p tcp -j {tcp_out}",f"{response} -p udp -j {udp_out}",f"{response} -j {meter_out}",f"{response} -j ACCEPT",f"-A {g} -j DROP"]
  for chain_name,table in ((meter_in,"mangle"),(meter_up,"filter"),(meter_out,"filter"),(dns_in,"mangle"),(tcp_in,"mangle"),(udp_in,"mangle"),(dns_out,"filter"),(tcp_out,"filter"),(udp_out,"filter")):restore(exe,table,[f"-F {chain_name}",f"-A {chain_name} -j RETURN"],None,m)
  restore(exe,"nat",[f"-F {nat_chain}",f"-A {nat_chain} -m mark --mark 0x{cap:x}/0x{mask:x} -j ACCEPT",f"-A {nat_chain} -m mark --mark 0x{up:x}/0x{mask:x} -j MASQUERADE"],None,m);restore(exe,"filter",uplink_rules,None,m);restore(exe,"mangle",gateway_rules,None,m);restore(exe,"mangle",capture,None,m);restore(exe,"filter",guard,None,m);restore(exe,"raw",[f"-F {raw_return}",f"-A {raw_return} -j ACCEPT"],None,m)
  deleted=run([tool("conntrack"),"-D","-f","ipv4" if f=="4" else "ipv6","-s",a],capture=True,check=False)
  if deleted.returncode not in (0,1):raise Error("netfilter_failed")
def container_netns(m):
 data=runtime_inspect(m);state=data.get("State",{})
 if state.get("Running") is not True or not isinstance(state.get("Pid"),int) or state["Pid"]<=1:raise Error("container_not_running")
 pid=state["Pid"]
 try:
  raw=Path(f"/proc/{pid}/stat").read_text();start=int(raw[raw.rfind(")")+2:].split()[19]);inode=Path(f"/proc/{pid}/ns/net").stat().st_ino
 except Exception as exc:raise Error("runtime_identity_mismatch") from exc
 if runtime_inspect(m).get("State",{}).get("Pid")!=pid:raise Error("runtime_identity_mismatch")
 return pid,start,inode
def android_ipv6(m,pid,repair=False):
 base=[tool("nsenter"),"--target",str(pid),"--net",tool("ip")];address=m["android"]["ipv6"];network=ipaddress.ip_network(address+"/64",strict=False);gateway=str(network.network_address+1);interface="eth0"
 try:
  interface_index=integer(int(run([*base,"-o","link","show","dev",interface],capture=True,code="ipv6_unsupported").stdout.decode("ascii","strict").split(":",1)[0]),1,(1<<31)-1)
 except (ValueError,IndexError,UnicodeError) as exc:raise Error("ipv6_unsupported") from exc
 table=str(1000+interface_index)
 if repair:
  run([*base,"-6","address","replace",address+"/64","dev",interface,"nodad"],code="ipv6_unsupported")
  run([*base,"-6","route","replace","table",table,"default","via",gateway,"dev",interface,"proto","static"],code="ipv6_unsupported")
 assigned=run([*base,"-6","address","show","dev",interface,"to",address+"/128"],capture=True,code="ipv6_unsupported").stdout.decode("ascii","strict").split()
 routed=run([*base,"-6","route","show","table",table,"default"],capture=True,code="ipv6_unsupported").stdout.decode("ascii","strict").split()
 if address+"/64" not in assigned or not all(token in routed for token in ("default","via",gateway,"dev",interface)):raise Error("ipv6_unsupported")
def proc_path(m,name):
 if name not in ("process","pending-process"):raise Error("internal_contract_error")
 return RUN/m["resourceTag"]/(name+".json")
def identity(m,pid):
 try:r=Path(f"/proc/{pid}/stat").read_text();start=int(r[r.rfind(")")+2:].split()[19]);exe=Path(f"/proc/{pid}/exe").resolve(strict=True);ino=Path(f"/proc/{pid}/ns/net").stat().st_ino;expected=(Path("/run/netns")/m["proxyNamespace"]).stat().st_ino
 except Exception as e:raise Error("process_identity_mismatch") from e
 if exe!=BINARY or sha(exe)!=m["engine"]["binarySha256"] or ino!=expected:raise Error("process_identity_mismatch")
 return {"pid":pid,"starttime":start,"binarySha256":m["engine"]["binarySha256"],"netnsInode":ino}
def runtime_dir(m):
 mkdir(RUN,0o755);path=RUN/m["resourceTag"];mkdir(path,0o711);s=path.lstat()
 if (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))!=(0,0,0o711):raise Error("unsafe_path")
 return path
def process_files(m,o,p,c,g,state_name):
 account=pwd.getpwnam(m["users"]["proxy"]);runtime=runtime_dir(m);state=runtime/state_name;owned_dir(state,account.pw_uid,account.pw_gid,0o700);remember(m,o,{"kind":"tree","path":str(state),"uid":account.pw_uid,"gid":account.pw_gid});root_file(p);config=runtime/f"config-{c}-{g}.yaml";data=p.read_bytes();atomic(config,data,0o640,0,account.pw_gid);remember(m,o,{"kind":"file","path":str(config),"sha256":hashlib.sha256(data).hexdigest()});return config,state
def launch(m,o,p,c,g,n):
 validate_binary(m)
 uid,gid=ensure_user(m["users"]["proxy"],m["_state"]);config,state=process_files(m,o,p,c,g,f"mihomo-{c}-{g}")
 log_fd=os.open(os.devnull,os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 child=subprocess.Popen([*netns_command(m["proxyNamespace"]),tool("setpriv"),"--reuid",str(uid),"--regid",str(gid),"--init-groups","--inh-caps=+net_raw","--ambient-caps=+net_raw","--bounding-set=-all,+net_raw",str(SANDBOX),"--binary",str(BINARY),"--config",str(config),"--state",str(state)],stdin=subprocess.DEVNULL,stdout=log_fd,stderr=subprocess.STDOUT,close_fds=True,start_new_session=True);os.close(log_fd)
 deadline=time.monotonic()+5
 while time.monotonic()<deadline:
  if child.poll() is not None:raise Error("engine_start_failed")
  try:record=identity(m,child.pid);record.update(supervisor="systemd-unit",candidate=c,generation=g);atomic(proc_path(m,n),json.dumps(record,sort_keys=True,separators=(",",":")).encode()+b"\n",0o600);return child
  except Error:time.sleep(.05)
 raise Error("engine_start_failed")
def checked_process(m,path,generation,candidate):
 record=read_json(path,"process_identity_mismatch");pid=record.get("pid")
 if not isinstance(pid,int):raise Error("process_identity_mismatch")
 current=identity(m,pid)
 if any(record.get(key)!=value for key,value in current.items()) or record.get("generation")!=generation or record.get("candidate")!=candidate or record.get("supervisor")!="systemd-unit":raise Error("process_identity_mismatch")
 return record
def health(m,child,ports,secret,udp_allowed,record=None):
 deadline=time.monotonic()+20
 while time.monotonic()<deadline:
  if child is not None and child.poll() is not None:break
  if record is not None:
   try:checked_process(m,proc_path(m,record["stateName"]),record["generation"],record["candidate"])
   except Error:break
  dual=run([*netns_command(m["proxyNamespace"]),tool("sysctl"),"-n","net.ipv6.bindv6only"],capture=True,check=False)
  udp_ready=all(socket_bound(m,"u",family,ports[0][1][0 if family=="4" else 1])==udp_allowed for family in ("4","6"))
  if not dual.returncode and dual.stdout.strip()==b"0" and all(socket_bound(m,"t",family,ports[0][0][0 if family=="4" else 1]) for family in ("4","6")) and udp_ready and all(socket_bound(m,protocol,"6",ports[1]) for protocol in ("t","u")) and socket_bound(m,"t","4",ports[2]):
   data=("silent\nfail\nmax-time = 2\n"+f'header = "Authorization: Bearer {secret}"\n').encode();response=run([*netns_command(m["proxyNamespace"]),tool("curl"),"--config","-",f"http://127.0.0.1:{ports[2]}/version"],data=data,check=False)
   if not response.returncode:return
  time.sleep(.25)
 raise Error("engine_health_failed")
def outbound_ready(m,controller_port,secret):
 data=("silent\nfail\nmax-time = 8\n"+f'header = "Authorization: Bearer {secret}"\n').encode()
 url=(f"http://127.0.0.1:{controller_port}/proxies/GLOBAL/delay"
      "?url=https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout=7000")
 for _ in range(3):
  response=run([*netns_command(m["proxyNamespace"]),tool("curl"),"--config","-",url],data=data,capture=True,check=False)
  if not response.returncode:
   try:delay=json.loads(response.stdout).get("delay")
   except (json.JSONDecodeError,AttributeError):delay=None
   if isinstance(delay,int) and not isinstance(delay,bool) and delay>=0:return
  time.sleep(.25)
 raise Error("engine_health_failed")
def stop(m,n,child=None):
 p=proc_path(m,n)
 if not p.exists():return
 record=read_json(p,"process_identity_mismatch");pid=record.get("pid")
 if not isinstance(pid,int) or pid<=1:raise Error("process_identity_mismatch")
 try:pidfd=os.pidfd_open(pid,0)
 except ProcessLookupError:p.unlink();return
 except (AttributeError,OSError) as exc:raise Error("pidfd_unsupported") from exc
 try:
  try:current=identity(m,pid)
  except Error:p.unlink();return
  if any(record.get(key)!=value for key,value in current.items()):p.unlink();return
  signal.pidfd_send_signal(pidfd,signal.SIGTERM);poller=select.poll();poller.register(pidfd,select.POLLIN)
  if not poller.poll(10000):
   signal.pidfd_send_signal(pidfd,signal.SIGKILL);poller.poll(2000)
  if child is not None:
   try:child.wait(timeout=0)
   except subprocess.TimeoutExpired:pass
 finally:os.close(pidfd)
 p.unlink()
def candidate_config(m,path,expected_name):
 root_file(path);config=json.loads(path.read_text());candidate,tproxy_port,dns_port,controller_port,secret,udp_allowed=validate_config(m,config)
 if candidate!=expected_name:raise Error("config_invalid")
 return config,tproxy_port,dns_port,controller_port,secret,udp_allowed
def apply_stage(name,function,*arguments):
 try:return function(*arguments)
 except Error as exc:
  if exc.code=="resource_conflict":raise Error(name+"_conflict") from exc
  raise
def apply(m,o,target="candidate",commit=False,expected_generation=None):
 if target=="previous":
  quarantine(m,o);stop(m,"pending-process");previous=o.get("previous")
  if not isinstance(previous,dict) or not proc_path(m,"process").exists():
   o["candidate"]=o["previous"]=None;save_owner(m,o);return
  config_path=Path(m["paths"]["config"]);_,tp,dp,cp,secret,udp_allowed=candidate_config(m,config_path,previous["name"]);record=checked_process(m,proc_path(m,"process"),previous["generation"],previous["name"])
  configure(m,previous["name"],tp,dp,udp_allowed);health(m,None,(tp,dp,cp),secret,udp_allowed,{"stateName":"process","generation":record["generation"],"candidate":record["candidate"]});activate(m,previous["name"])
  o["appliedGeneration"],o["activeCandidate"]=previous["generation"],previous["name"];o["candidate"]=o["previous"]=None;o["phase"]="applied";save_owner(m,o);return
 if target!="candidate":raise Error("ipc_request_invalid")
 if expected_generation is not None:
  candidate=o.get("candidate")
  if not isinstance(candidate,dict) or candidate.get("generation")!=expected_generation:raise Error("ipc_request_invalid")
 if commit:
  if o["phase"]!="applied-pending" or not isinstance(o.get("candidate"),dict):raise Error("apply_not_pending")
  meta=o["candidate"];path=Path(meta["path"]);_,tp,dp,cp,secret,udp_allowed=candidate_config(m,path,meta["name"]);pending=checked_process(m,proc_path(m,"pending-process"),meta["generation"],meta["name"])
  configure(m,meta["name"],tp,dp,udp_allowed);health(m,None,(tp,dp,cp),secret,udp_allowed,{"stateName":"pending-process","generation":pending["generation"],"candidate":pending["candidate"]});activate(m,meta["name"])
  config_path=Path(m["paths"]["config"]);candidate_bytes=path.read_bytes();proxy_user=pwd.getpwnam(m["users"]["proxy"])
  stop(m,"process");os.replace(proc_path(m,"pending-process"),proc_path(m,"process"));atomic(config_path,candidate_bytes,0o640,0,proxy_user.pw_gid)
  o["appliedGeneration"],o["activeCandidate"]=meta["generation"],meta["name"];o["candidate"]=o["previous"]=None;o["phase"]="applied";save_owner(m,o);return
 meta=o.get("candidate")
 if not isinstance(meta,dict):raise Error("config_missing")
 path=Path(meta["path"])
 if sha(path)!=meta["sha256"]:raise Error("config_digest_mismatch")
 _,tproxy_port,dns_port,controller_port,secret,udp_allowed=candidate_config(m,path,meta["name"])
 apply_stage("baseline",quarantine,m,o);prerequisites();validate_binary(m)
 apply_stage("topology",topology,m,o);apply_stage("policy",policy,m,o);apply_stage("dataplane",dataplane,m,o)
 configure(m,meta["name"],tproxy_port,dns_port,udp_allowed)
 child=launch(m,o,path,meta["name"],meta["generation"],"pending-process")
 try:health(m,child,(tproxy_port,dns_port,controller_port),secret,udp_allowed);activate(m,meta["name"]);outbound_ready(m,controller_port,secret)
 except Error:quarantine(m,o);stop(m,"pending-process",child);raise
 o["previous"]={"generation":o["appliedGeneration"],"name":o["activeCandidate"]} if isinstance(o["appliedGeneration"],int) and o["activeCandidate"] in ("a","b") else None;o["phase"]="applied-pending";save_owner(m,o)
def _iptables_absent(command):
 indices=[index for index,value in enumerate(command) if Path(value).name in ("iptables","ip6tables")]
 if not indices:return False
 index=indices[-1];base=command[:index+1]
 if "-D" in command:
  check=list(command);check[check.index("-D")]="-C";return run(check,check=False).returncode!=0
 if "-X" in command:
  chain_name=command[command.index("-X")+1];table=command[command.index("-t")+1] if "-t" in command else "filter"
  return run([*base,"-w","-t",table,"-S",chain_name],check=False).returncode!=0
 if "-F" in command:
  chain_name=command[command.index("-F")+1];table=command[command.index("-t")+1] if "-t" in command else "filter"
  return run([*base,"-w","-t",table,"-S",chain_name],check=False).returncode!=0
 return False
def _ip_absent(command):
 if Path(command[0]).name!="ip":return False
 if "netns" in command and "del" in command:
  return not (Path("/run/netns")/command[command.index("del")+1]).exists()
 if "netns" in command and "exec" in command and not (Path("/run/netns")/command[command.index("exec")+1]).exists():return True
 if "link" in command and "del" in command:
  dev=command[command.index("del")+1] if command[command.index("del")+1]!="dev" else command[command.index("del")+2]
  prefix=command[:command.index("link")];return run([*prefix,"link","show","dev",dev],check=False).returncode!=0
 operation="rule" if "rule" in command else "route" if "route" in command else None
 if operation is None:return False
 index=command.index(operation);prefix=command[:index]
 if operation=="rule":
  priority=command[command.index("priority")+1];output=run([*prefix,"rule","show"],capture=True,check=False)
  return output.returncode!=0 or not any(line.lstrip().startswith(f"{priority}:") for line in output.stdout.decode("ascii","ignore").splitlines())
 table=command[command.index("table")+1];destination=command[command.index("table")+2];output=run([*prefix,"route","show","table",table],capture=True,check=False)
 return output.returncode!=0 or not any(destination in line.split() for line in output.stdout.decode("ascii","ignore").splitlines())
def flush_owned_chains(resources):
 for resource in resources:
  command=resource.get("delete")
  if resource.get("kind")!="command" or not isinstance(command,list) or "-X" not in command:continue
  flush=[("-F" if argument=="-X" else argument) for argument in command]
  result=run(flush,check=False)
  if result.returncode and not _iptables_absent(command):raise Error("cleanup_incomplete")
def remove_command_resource(resource):
 command=resource["delete"]
 if "-X" in command:
  flush=[("-F" if arg=="-X" else arg) for arg in command];result=run(flush,check=False)
  if result.returncode and not _iptables_absent(command):raise Error("cleanup_incomplete")
 result=run(command,check=False)
 if result.returncode and not (_iptables_absent(command) or _ip_absent(command)):raise Error("cleanup_incomplete")
def verify_off(m,o):
 if proc_path(m,"process").exists() or proc_path(m,"pending-process").exists():raise Error("off_unverified")
 ensure_baseline(m,o);topology(m,o);policy(m,o);dataplane(m,o);program_baseline(m,False);n=names(m)
 for family,exe in (("4",tool("iptables")),("6",tool("ip6tables"))):
  address=m["android"]["ipv4" if family=="4" else "ipv6"];hook_owner=f"xenoid-proxy/{m['resourceTag']}/DOCKER-USER/{m['runtimeEpoch']}/{m['generation']}";capture_owner=f"xenoid-proxy/{m['resourceTag']}/PREROUTING/{m['runtimeEpoch']}/{m['generation']}";restore_owner=f"xenoid-proxy/{m['resourceTag']}/{m['runtimeEpoch']}/{m['generation']}"
  check_rule(exe,"filter","DOCKER-USER",["-i",m["bridgeName"],"-m","mac","--mac-source",m["android"]["mac"],"-j",n["guard"+family]],hook_owner);check_rule(exe,"mangle","PREROUTING",["-i",m["bridgeName"],"-m","mac","--mac-source",m["android"]["mac"],"-j",n["capture"+family]],capture_owner);check_rule(exe,"raw","PREROUTING",["-i",m["veth"]["host"],"-d",address,"-j",n["rawReturn"+family]],capture_owner);check_rule(exe,"raw",n["rawReturn"+family],["-j","DROP"],restore_owner)
 if not (Path("/run/netns")/m["proxyNamespace"]).exists() or run([tool("ip"),"link","show","dev",m["veth"]["host"]],check=False).returncode:raise Error("off_unverified")
def off(m,o,expected_generation=None):
 quarantine(m,o);stop(m,"pending-process");stop(m,"process")
 validate_provider_cache(m,True);prepare_runtime(m,o);program_baseline(m,False);verify_off(m,o)
 latch=m["_state"]/"mustBlock";root_file(latch,0o600);latch.unlink();requested=expected_generation if expected_generation is not None else m["generation"];o["appliedGeneration"]=max(o["appliedGeneration"] or 0,requested);o["activeCandidate"]=None;o["candidate"]=o["previous"]=None;o["phase"]="off";save_owner(m,o)
def counter(exe,table,chain_name,inside=False):
 base=[*netns_command(inside),tool(exe)] if inside else [tool(exe)]
 result=run([*base,"-w","-t",table,"-L",chain_name,"-n","-v","-x"],capture=True,check=False);packets=byte_count=0
 for line in result.stdout.decode(errors="ignore").splitlines():
  fields=line.split()
  if len(fields)>1 and fields[0].isdigit() and fields[1].isdigit():packets+=int(fields[0]);byte_count+=int(fields[1])
 return packets,byte_count
def socket_bound(m,protocol,family,port):
 for candidate in ((family,) if family!="4" else ("4","6")):
  output=run([*netns_command(m["proxyNamespace"]),tool("ss"),"-H",f"-ln{protocol}{candidate}"],capture=True,code="engine_structure_mismatch").stdout.decode("ascii","ignore")
  if any(field.endswith(f":{port}") for line in output.splitlines() for field in line.split()):return True
 return False
def validate_ipc(m):
 record=read_json(server_record(m),"ipc_unavailable")
 try:current=server_id(record.get("pid"))
 except Exception as exc:raise Error("ipc_unavailable") from exc
 if current!=record:raise Error("ipc_unavailable")
 try:metadata=ipc_path(m).lstat();agent=pwd.getpwnam(m["users"]["agent"])
 except (OSError,KeyError) as exc:raise Error("ipc_unavailable") from exc
 if not stat.S_ISSOCK(metadata.st_mode) or (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))!=(0,agent.pw_gid,0o660):raise Error("ipc_unavailable")
 return True
def status(m,o,expected_generation=None):
 n=names(m);validate_control();validate_provider_cache(m);validate_ipc(m);phase_state=o["phase"];process=None;generation=None;candidate=None;config_path=None
 if phase_state=="applied":
  process=proc_path(m,"process");generation=o["appliedGeneration"];candidate=o["activeCandidate"];config_path=Path(m["paths"]["config"])
 elif phase_state=="applied-pending":
  meta=o.get("candidate")
  if isinstance(meta,dict):process=proc_path(m,"pending-process");generation=meta["generation"];candidate=meta["name"];config_path=Path(meta["path"])
 structural=process is not None and process.exists() and isinstance(generation,int) and candidate in ("a","b")
 if structural:
  validate_accounts(m);validate_binary(m);checked_process(m,process,generation,candidate)
  _,configured_ports,_,_,_,udp_allowed=candidate_config(m,config_path,candidate)
  for family,exe in (("4",tool("iptables")),("6",tool("ip6tables"))):
   chain_specs=((n["guard"+family],"filter",False),(n["capture"+family],"mangle",False),(n["rawReturn"+family],"raw",False),(n["uplink"+family],"filter",False),(n["gatewayMark"+family],"mangle",False),(n["nat"+family],"nat",False),(n["meterIn"+family],"mangle",False),(n["meterUp"+family],"filter",False),(n["meterOut"+family],"filter",False),(n["meterDnsIn"+family],"mangle",False),(n["meterTcpIn"+family],"mangle",False),(n["meterUdpIn"+family],"mangle",False),(n["meterDnsOut"+family],"filter",False),(n["meterTcpOut"+family],"filter",False),(n["meterUdpOut"+family],"filter",False),(n["tproxy"+family],"mangle",True),(n["dns"+family],"nat",True),(n["output"+family],"filter",True),(n["mark"+family],"mangle",True),(n["input"+family],"filter",True),(n["meterDnsUp"+family],"nat",True),(n["meterTcpUp"+family],"mangle",True),(n["meterUdpUp"+family],"mangle",True))
   for chain_name,table,inside in chain_specs:
    if run([*pref(m,exe,inside),"-w","-t",table,"-S",chain_name],check=False).returncode:raise Error("engine_structure_mismatch")
   address=m["android"]["ipv4" if family=="4" else "ipv6"];restore_owner=f"xenoid-proxy/{m['resourceTag']}/{m['runtimeEpoch']}/{m['generation']}";hook_owner=f"xenoid-proxy/{m['resourceTag']}/DOCKER-USER/{m['runtimeEpoch']}/{m['generation']}";capture_owner=f"xenoid-proxy/{m['resourceTag']}/PREROUTING/{m['runtimeEpoch']}/{m['generation']}";nat_owner=f"xenoid-proxy/{m['resourceTag']}/POSTROUTING/{m['runtimeEpoch']}/{m['generation']}"
   ports,dp,_=((((7893,7895),(7897,7899)),1053,9091) if candidate=="a" else (((7894,7896),(7898,7900)),1054,9092));tcp_port=ports[0][0 if family=="4" else 1];udp_port=ports[1][0 if family=="4" else 1];cap,resp,up=marks(m,candidate);mask=m["routing"]["mask"]
   check_rule(exe,"mangle",n["gatewayMark"+family],["-d",address,"-j","MARK","--set-xmark",f"0x{resp:x}/0x{mask:x}"],restore_owner);check_rule(exe,"mangle",n["gatewayMark"+family],["!","-d",address,"-j","MARK","--set-xmark",f"0x{up:x}/0x{mask:x}"],restore_owner);check_rule(exe,"raw","PREROUTING",["-i",m["veth"]["host"],"-d",address,"-j",n["rawReturn"+family]],capture_owner);check_rule(exe,"raw",n["rawReturn"+family],["-j","ACCEPT"],restore_owner);check_rule(exe,"filter",n["uplink"+family],["-i",m["veth"]["host"],"-o",m["bridgeName"],"-d",address,"-m","mark","--mark",f"0x{resp:x}/0x{mask:x}","-m","conntrack","--ctstate","ESTABLISHED,RELATED","-j","RETURN"],restore_owner);check_rule(exe,"nat","POSTROUTING",["-s",address,"-j",n["nat"+family]],nat_owner);check_rule(exe,"nat",n["nat"+family],["-m","mark","--mark",f"0x{cap:x}/0x{mask:x}","-j","ACCEPT"],restore_owner);check_rule(pref(m,exe,True),"nat",n["dns"+family],["-p","tcp","-j","REDIRECT","--to-ports",str(tcp_port)],restore_owner);check_rule(pref(m,exe,True),"nat",n["dns"+family],["-p","udp","--dport","53","-j","REDIRECT","--to-ports",str(dp)],restore_owner)
   if udp_allowed:check_rule(pref(m,exe,True),"mangle",n["tproxy"+family],["-p","udp","-j","TPROXY","--on-port",str(udp_port),"--tproxy-mark",f"0x{cap:x}/0x{mask:x}"],restore_owner)
   else:check_rule(pref(m,exe,True),"mangle",n["tproxy"+family],["-p","udp","-j","DROP"],restore_owner)
   if family=="6":check_rule(pref(m,exe,True),"mangle",n["tproxy6"],["-p","ipv6-icmp","--icmpv6-type","135","-m","hl","--hl-eq","255","-j","RETURN"],restore_owner)
  android_ipv6(m,container_netns(m)[0])
  proxy_ports,dns_port,controller_port=(((7893,7895),(7897,7899)),1053,9091) if candidate=="a" else (((7894,7896),(7898,7900)),1054,9092)
  for key in ("net.ipv4.conf.all.rp_filter","net.ipv4.conf.default.rp_filter",f"net.ipv4.conf.{m['veth']['proxy']}.rp_filter"):
   if run([*netns_command(m["proxyNamespace"]),tool("sysctl"),"-n",key],capture=True,code="rp_filter_unsupported").stdout.strip()!=b"0":raise Error("rp_filter_unsupported")
  for key in ("net.ipv4.conf.all.src_valid_mark","net.ipv4.conf.default.src_valid_mark",f"net.ipv4.conf.{m['veth']['proxy']}.src_valid_mark"):
   if run([*netns_command(m["proxyNamespace"]),tool("sysctl"),"-n",key],capture=True,code="rp_filter_unsupported").stdout.strip()!=b"0":raise Error("rp_filter_unsupported")
  for family,address in (("-4","198.18.0.1/32"),("-6","fd00::1/128")):
   if run([*netns_command(m["proxyNamespace"]),tool("ip"),family,"address","show","dev","lo","to",address],capture=True,code="topology_peer_missing").stdout.strip()==b"":raise Error("topology_peer_missing")
  if run([*netns_command(m["proxyNamespace"]),tool("sysctl"),"-n","net.ipv6.bindv6only"],capture=True,code="ipv6_unsupported").stdout.strip()!=b"0":raise Error("ipv6_unsupported")
  if not all(socket_bound(m,"t",family,configured_ports[0][0 if family=="4" else 1]) for family in ("4","6")) or not all(socket_bound(m,"u",family,configured_ports[1][0 if family=="4" else 1])==udp_allowed for family in ("4","6")) or not all(socket_bound(m,protocol,"6",dns_port) for protocol in ("t","u")) or not socket_bound(m,"t","4",controller_port):raise Error("engine_structure_mismatch")
 offok=phase_state=="off" and not proc_path(m,"process").exists() and not proc_path(m,"pending-process").exists()
 if offok:
  verify_off(m,o)
  if (m["_state"]/"mustBlock").exists():raise Error("off_unverified")
 phase={"quarantine":"quarantined","new":"applying","prepared":"applying","configured":"applying","applied-pending":"active","applied":"active","off":"off"}.get(phase_state)
 if phase is None:raise Error("ownership_invalid")
 counters={}
 if structural:
  aggregate=(counter("iptables","mangle",n["meterIn4"]),counter("iptables","filter",n["meterUp4"]),counter("iptables","filter",n["meterOut4"]))
  for name,value in zip(("ingress","proxyUplink","egress"),aggregate):counters[name],counters[name+"Bytes"]=value
  for family in ("4","6"):
   exe="iptables" if family=="4" else "ip6tables"
   for capability,role,table,inside in (("Dns","meterDnsIn","mangle",False),("Tcp","meterTcpIn","mangle",False),("Udp","meterUdpIn","mangle",False),("Dns","meterDnsUp","nat",True),("Tcp","meterTcpUp","mangle",True),("Udp","meterUdpUp","mangle",True),("Dns","meterDnsOut","filter",False),("Tcp","meterTcpOut","filter",False),("Udp","meterUdpOut","filter",False)):
    stage="Ingress" if role.endswith("In") else "Uplink" if role.endswith("Up") else "Egress";counters[f"v{family}{capability}{stage}"]=counter(exe,table,n[role+family],m["proxyNamespace"] if inside else False)[0]
 else:counters={key:0 for key in ("ingress","proxyUplink","egress","ingressBytes","proxyUplinkBytes","egressBytes")}
 for family in ("4","6"):
  for capability in ("Dns","Tcp","Udp"):
   for stage in ("Ingress","Uplink","Egress"):counters.setdefault(f"v{family}{capability}{stage}",0)
 wire_generation=generation if structural else o["appliedGeneration"] if o["appliedGeneration"] is not None else m["generation"]
 if expected_generation is not None:wire_generation=max(wire_generation,expected_generation)
 capabilities={f"v{family}{capability}Proxy":False for family in ("4","6") for capability in ("Dns","Tcp","Udp")}
 return {"ok":True,"instanceId":m["instanceId"],"resourceTag":m["resourceTag"],"runtimeEpoch":m["runtimeEpoch"],"generation":wire_generation,"manifestDigest":m["manifestDigest"],"phase":phase,"structuralApplied":structural or offok,"dataPlaneVerified":offok,"capabilities":capabilities,"counters":counters,"selectedNode":"","nodeCount":0}
def remove_owned_tree(path,uid,gid):
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 try:root_fd=os.open(path,flags);root=os.fstat(root_fd)
 except OSError as exc:raise Error("cleanup_incomplete") from exc
 if (root.st_uid,root.st_gid,stat.S_IMODE(root.st_mode))!=(uid,gid,0o700):os.close(root_fd);raise Error("cleanup_incomplete")
 count=[0]
 def visit(directory_fd,depth):
  if depth>16:raise Error("cleanup_incomplete")
  try:names=[entry.name for entry in os.scandir(directory_fd)]
  except OSError as exc:raise Error("cleanup_incomplete") from exc
  for name in names:
   count[0]+=1
   if count[0]>4096:raise Error("cleanup_incomplete")
   try:item=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
   except OSError as exc:raise Error("cleanup_incomplete") from exc
   if item.st_uid!=uid or item.st_gid!=gid or item.st_dev!=root.st_dev or stat.S_ISLNK(item.st_mode):raise Error("cleanup_incomplete")
   if stat.S_ISDIR(item.st_mode):
    try:child=os.open(name,flags,dir_fd=directory_fd)
    except OSError as exc:raise Error("cleanup_incomplete") from exc
    try:visit(child,depth+1)
    finally:os.close(child)
    os.rmdir(name,dir_fd=directory_fd)
   elif stat.S_ISREG(item.st_mode) and item.st_nlink==1:os.unlink(name,dir_fd=directory_fd)
   else:raise Error("cleanup_incomplete")
 try:visit(root_fd,0)
 finally:os.close(root_fd)
 try:parent_fd=os.open(path.parent,flags)
 except OSError as exc:raise Error("cleanup_incomplete") from exc
 try:os.rmdir(path.name,dir_fd=parent_fd)
 finally:os.close(parent_fd)


def remove_state_file(path,mode,gid=None):
 try:s=path.lstat()
 except FileNotFoundError:return
 root_file(path,mode)
 if s.st_nlink!=1 or (gid is not None and s.st_gid!=gid):raise Error("cleanup_incomplete")
 path.unlink()
def remove_state_remainder(m):
 state=m["_state"];agent=pwd.getpwnam(m["users"]["agent"]);compiler=pwd.getpwnam(m["users"]["compiler"]);proxy=pwd.getpwnam(m["users"]["proxy"])
 cache=state/"provider-cache"
 if cache.exists():validate_provider_cache(m);remove_owned_tree(cache,agent.pw_uid,agent.pw_gid)
 build=state/"sandbox-build"
 if build.exists():remove_owned_tree(build,compiler.pw_uid,compiler.pw_gid)
 candidates=state/"candidates"
 if candidates.exists():
  for child in candidates.iterdir():
   metadata=child.lstat()
   if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))!=(0,proxy.pw_gid,0o750) or any(child.iterdir()):raise Error("cleanup_incomplete")
   child.rmdir()
  metadata=candidates.lstat()
  if (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))!=(0,0,0o700):raise Error("cleanup_incomplete")
  candidates.rmdir()
 remove_state_file(state/"config.yaml",0o640,proxy.pw_gid);remove_state_file(state/"agent.key",0o400);remove_state_file(state/"agent-status.json",0o600);remove_state_file(state/"agent.lock",0o600);remove_state_file(state/"manifest.json",0o600)
 metadata=state.lstat()
 if (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))!=(0,0,0o700) or any(state.iterdir()):raise Error("cleanup_incomplete")
 state.rmdir()
def cleanup(m,o):
 exists=live(m,True,True)
 if exists:
  container=runtime_inspect(m,allow_stopped=True)
  if container.get("State",{}).get("Running") is not False:raise Error("container_running")
 service=f"xenoid-proxy-agent@{m['resourceTag']}.service"
 if systemd():
  stopped=run([tool("systemctl"),"stop",service],capture=True,check=False)
  if stopped.returncode not in (0,5):raise Error("cleanup_incomplete")
 quarantine(m,o);stop_server(m);stop(m,"pending-process");stop(m,"process")
 flush_owned_chains(o["resources"])
 while o["resources"]:
  resource=o["resources"][-1]
  if resource["kind"]=="file":
   path=Path(resource["path"])
   if path.exists():
    if sha(path)!=resource["sha256"]:raise Error("cleanup_incomplete")
    path.unlink()
  elif resource["kind"]=="tree":
   path=Path(resource["path"])
   if path.exists():remove_owned_tree(path,resource["uid"],resource["gid"])
  elif resource["kind"]=="command":remove_command_resource(resource)
  else:raise Error("ownership_invalid")
  o["resources"].pop();save_owner(m,o)
 remove_state_file(m["_path"],0o600)
 runtime=RUN/m["resourceTag"]
 if runtime.exists():
  diagnostic=runtime/"diagnostic.log"
  if diagnostic.exists():
   proxy=pwd.getpwnam(m["users"]["proxy"]);metadata=diagnostic.lstat()
   if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode),metadata.st_nlink)!=(proxy.pw_uid,proxy.pw_gid,0o600,1):raise Error("cleanup_incomplete")
   diagnostic.unlink()
  try:runtime.rmdir()
  except OSError as exc:raise Error("cleanup_incomplete") from exc
 latch=m["_state"]/"mustBlock";root_file(latch,0o600)
 try:latch_record=json.loads(latch.read_text())
 except (OSError,json.JSONDecodeError) as exc:raise Error("cleanup_incomplete") from exc
 if latch_record!={"instanceId":m["instanceId"],"runtimeEpoch":m["runtimeEpoch"]}:raise Error("cleanup_incomplete")
 owner_path(m).unlink();latch.unlink()
 remove_state_remainder(m)
def recover_epoch_transaction(m,o):
 temporary=[resource for resource in o["resources"] if resource.get("scope")=="epoch-temporary"]
 if not temporary:return
 quarantine(m,o)
 for resource in reversed(temporary):
  remove_command_resource(resource);o["resources"].remove(resource);save_owner(m,o)
def rotate_owner(m,o):
 old=dict(m);old["runtimeEpoch"]=o["runtimeEpoch"];old["generation"]=o["manifestGeneration"];old["manifestDigest"]=o["manifestDigest"]
 record_path=server_record(old)
 if record_path.exists():
  record=read_json(record_path,"process_identity_mismatch")
  if record.get("pid")==os.getpid():raise Error("instance_busy")
 live(m);quarantine(old,o);comment=f"xenoid-proxy/{m['resourceTag']}/epoch-rotation/{m['runtimeEpoch']}"
 for executable in (tool("iptables"),tool("ip6tables")):
  args=["-i",m["bridgeName"],"-m","mac","--mac-source",m["android"]["mac"],"-m","comment","--comment",comment,"-j","DROP"]
  rule(m,o,executable,"filter","DOCKER-USER",args,True,scope="epoch-temporary")
 stop_server(old);stop(old,"pending-process");stop(old,"process")
 flush_owned_chains(o["resources"])
 temporary=[resource for resource in o["resources"] if resource.get("scope")=="epoch-temporary"]
 for resource in list(reversed(o["resources"])):
  if resource in temporary:continue
  if resource["kind"]=="file":
   path=Path(resource["path"])
   if path.exists():
    if sha(path)!=resource["sha256"]:raise Error("cleanup_incomplete")
    path.unlink()
  elif resource["kind"]=="tree":
   path=Path(resource["path"])
   if path.exists():remove_owned_tree(path,resource["uid"],resource["gid"])
  else:remove_command_resource(resource)
  o["resources"].remove(resource);save_owner(old,o)
 fresh={"schema":OWNER_SCHEMA,"instanceId":m["instanceId"],"resourceTag":m["resourceTag"],"runtimeEpoch":m["runtimeEpoch"],"manifestDigest":m["manifestDigest"],"leaseDigest":lease_digest(m),"manifestGeneration":m["generation"],"appliedGeneration":None,"phase":"rotating","activeCandidate":None,"candidate":None,"previous":None,"binarySha256":m["engine"]["binarySha256"],"pythonPath":str(Path(sys.executable).resolve()),"resources":temporary};save_owner(m,fresh);recover_epoch_transaction(m,fresh)
 return fresh
def ipc_path(m):return RUN/m["resourceTag"]/"engine.sock"
def server_record(m):return RUN/m["resourceTag"]/"engine-server.json"
def server_id(pid):
 r=Path(f"/proc/{pid}/stat").read_text();exe=Path(f"/proc/{pid}/exe").resolve(strict=True);expected=Path(sys.executable).resolve()
 if exe!=expected:raise Error("process_identity_mismatch")
 return {"pid":pid,"starttime":int(r[r.rfind(")")+2:].split()[19]),"pythonPath":str(expected),"pythonSha256":sha(expected)}
def stop_server(m):
 record_path=server_record(m)
 if not record_path.exists():return
 record=read_json(record_path,"process_identity_mismatch");pid=record.get("pid")
 if not isinstance(pid,int) or pid<=1:raise Error("process_identity_mismatch")
 try:pidfd=os.pidfd_open(pid,0)
 except ProcessLookupError:
  record_path.unlink()
  try:ipc_path(m).unlink()
  except FileNotFoundError:pass
  return
 except (AttributeError,OSError) as exc:raise Error("pidfd_unsupported") from exc
 try:
  try:current=server_id(pid)
  except Exception:current=None
  if current!=record:
   record_path.unlink()
   try:ipc_path(m).unlink()
   except FileNotFoundError:pass
   return
  signal.pidfd_send_signal(pidfd,signal.SIGTERM);poller=select.poll();poller.register(pidfd,select.POLLIN)
  if not poller.poll(5000):signal.pidfd_send_signal(pidfd,signal.SIGKILL);poller.poll(2000)
 finally:os.close(pidfd)
 record_path.unlink()
 try:ipc_path(m).unlink()
 except FileNotFoundError:pass
def sealed(fd):
 req=sum(getattr(fcntl,x,v) for x,v in (("F_SEAL_SEAL",1),("F_SEAL_SHRINK",2),("F_SEAL_GROW",4),("F_SEAL_WRITE",8)));s=os.fstat(fd)
 if fcntl.fcntl(fd,getattr(fcntl,"F_GET_SEALS",1034))&req!=req or not stat.S_ISREG(s.st_mode) or not 0<s.st_size<=MAX_CONFIG:raise Error("ipc_fd_invalid")
 os.lseek(fd,0,0);data=os.read(fd,MAX_CONFIG+1)
 if len(data)!=s.st_size:raise Error("ipc_fd_invalid")
 return data
def worker(m,kind):
 path=Path(f"/usr/libexec/xenoid-proxy-{'compile' if kind=='Compiler' else 'fetch'}-worker.py");root_file(path,0o555);user=m["users"]["compiler" if kind=="Compiler" else "fetcher"];uid,gid=ensure_user(user,m["_state"]);read_input,write_input=os.pipe2(os.O_CLOEXEC);read_output,write_output=os.pipe2(os.O_CLOEXEC);devnull=os.open("/dev/null",os.O_WRONLY)
 command=[tool("setpriv"),"--pdeathsig","KILL","--reuid",str(uid),"--regid",str(gid),"--init-groups","--no-new-privs","--bounding-set=-all",str(path)]
 if kind=="Compiler":command=[tool("unshare"),"--net","--",*command]
 process=subprocess.Popen(command,stdin=read_input,stdout=write_output,stderr=devnull,cwd="/",env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C","LC_ALL":"C"},close_fds=True,start_new_session=True)
 os.close(read_input);os.close(write_output);os.close(devnull);return process,write_input,read_output
def request_lock():
 mkdir(LOCK.parent,0o755);descriptor=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600);deadline=time.monotonic()+20
 while True:
  try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB);return descriptor
  except BlockingIOError:
   if time.monotonic()>=deadline:os.close(descriptor);raise Error("engine_busy")
   time.sleep(.05)
def open_ipc_listener(m):
 runtime_dir(m);path=ipc_path(m);record_path=server_record(m)
 if record_path.exists():
  record=read_json(record_path,"process_identity_mismatch")
  try:current=server_id(record.get("pid"))
  except Exception:current=None
  if current==record:raise Error("instance_busy")
  record_path.unlink()
 try:path.unlink()
 except FileNotFoundError:pass
 listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC);listener.bind(str(path));_,gid=ensure_user(m["users"]["agent"],m["_state"]);os.chown(path,0,gid);os.chmod(path,0o660);listener.listen(8);return listener
def serve(m,listener):
 global _REQUEST_DEADLINE
 uid,gid=ensure_user(m["users"]["agent"],m["_state"]);workers={};parent=os.getppid();deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  try:parent_uid=Path(f"/proc/{parent}").stat().st_uid
  except OSError:break
  if parent_uid==uid:
   discard_key(m);break
  time.sleep(.02)
 while True:
  for worker_id,process in list(workers.items()):
   if process.poll() is not None:workers.pop(worker_id)
  connection,_=listener.accept();connection.settimeout(5);fds=array.array("i");response_fds=[];lock_fd=-1
  try:
   _pid,peer_uid,peer_gid=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
   if (peer_uid,peer_gid)!=(uid,gid):raise Error("ipc_peer_denied")
   discard_key(m)
   packet,ancillary,flags,_=connection.recvmsg(65536,socket.CMSG_SPACE(16))
   if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or not packet or len(packet)>65536:raise Error("ipc_request_invalid")
   for level,kind,data in ancillary:
    if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:fds.frombytes(data[:len(data)-len(data)%fds.itemsize])
   def pairs(values):
    result={}
    for key,value in values:
     if key in result:raise Error("ipc_request_invalid")
     result[key]=value
    return result
   request=json.loads(packet,object_pairs_hook=pairs)
   if json.dumps(request,ensure_ascii=True,sort_keys=True,separators=(",",":")).encode()!=packet:raise Error("ipc_request_invalid")
   exact(request,("schema","method","instanceId","resourceTag","runtimeEpoch","manifestDigest","generation","body"),"ipc_request_invalid")
   if request["schema"]!=IPC_SCHEMA or any(request[key]!=m[key] for key in ("instanceId","resourceTag","runtimeEpoch","manifestDigest")):raise Error("ipc_identity_mismatch")
   _REQUEST_DEADLINE=time.monotonic()+25;lock_fd=request_lock()
   manifest=load_manifest(str(m["_path"]));live(manifest);ownership=owner(manifest);method=request["method"];generation=integer(request["generation"],manifest["generation"],(1<<63)-1)
   if method=="writeConfig" and request["body"]=={} and len(fds)==1:write_config(manifest,ownership,sealed(fds[0]),generation);body={}
   elif method=="apply" and isinstance(request["body"],dict) and set(request["body"])=={"target","commit"} and isinstance(request["body"]["commit"],bool):apply(manifest,ownership,request["body"]["target"],request["body"]["commit"],generation);body=status(manifest,ownership,generation)
   elif method=="status" and request["body"]=={} and not fds:body=status(manifest,ownership,generation)
   elif method=="prepare" and request["body"]=={} and not fds:prepare_runtime(manifest,ownership);body={}
   elif method=="off" and request["body"]=={} and not fds:off(manifest,ownership,generation);body=status(manifest,ownership,generation)
   elif method=="quarantine" and request["body"]=={} and not fds:quarantine(manifest,ownership);body={}
   elif method in ("spawnCompiler","spawnFetcher") and request["body"]=={} and not fds:
    if len(workers)>=4:raise Error("worker_limit")
    process,write_input,read_output=worker(manifest,method[5:]);worker_id=os.urandom(16).hex();workers[worker_id]=process;response_fds=[write_input,read_output];body={"workerId":worker_id}
   elif method=="stopWorker" and isinstance(request["body"],dict) and set(request["body"])=={"workerId"} and isinstance(request["body"]["workerId"],str) and re.fullmatch(r"[0-9a-f]{32}",request["body"]["workerId"]):
    process=workers.pop(request["body"]["workerId"],None)
    if process is None:raise Error("worker_missing")
    try:os.killpg(process.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:
     try:os.killpg(process.pid,signal.SIGKILL)
     except ProcessLookupError:pass
     process.wait(timeout=2)
    body={}
   else:raise Error("ipc_request_invalid")
   output=json.dumps({"schema":IPC_SCHEMA,"ok":True,"body":body},sort_keys=True,separators=(",",":")).encode();rights=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",response_fds))] if response_fds else [];connection.sendmsg([output],rights)
  except Error as exc:connection.send(json.dumps({"schema":IPC_SCHEMA,"ok":False,"error":exc.code},sort_keys=True,separators=(",",":")).encode())
  except Exception:connection.send(json.dumps({"schema":IPC_SCHEMA,"ok":False,"error":"ipc_internal_error"},sort_keys=True,separators=(",",":")).encode())
  finally:
   _REQUEST_DEADLINE=None
   if lock_fd>=0:os.close(lock_fd)
   for descriptor in [*fds,*response_fds]:
    try:os.close(descriptor)
    except OSError:pass
   connection.close()
def service_launch(m,o):
 if o["phase"] not in ("prepared","configured","quarantine","off","applied","applied-pending"):raise Error("engine_not_prepared")
 validate_control();validate_accounts(m);quarantine(m,o);listener=open_ipc_listener(m);pid=os.fork()
 if pid==0:
  try:serve(m,listener)
  finally:os._exit(1)
 listener.close()
 try:
  record=server_id(pid);atomic(server_record(m),json.dumps(record,sort_keys=True,separators=(",",":")).encode()+b"\n",0o600)
  os.execv("/usr/libexec/xenoid-proxy-agent.py",["/usr/libexec/xenoid-proxy-agent.py","--manifest",str(m["_path"])])
 except BaseException:
  try:os.kill(pid,signal.SIGKILL)
  except ProcessLookupError:pass
  raise
def discard_key(m):
 path=Path(m["paths"]["key"])
 try:metadata=path.lstat()
 except FileNotFoundError:return
 root_file(path,0o400)
 if metadata.st_nlink!=1:raise Error("agent_key_invalid")
 path.unlink()
def parser():
 p=Parser(allow_abbrev=False);s=p.add_subparsers(dest="action",required=True)
 for x in ("check-control","prepare-host","install-control","install-asset","discard-key","prepare","write-config","apply","off","status","quarantine","cleanup","service"):q=s.add_parser(x,allow_abbrev=False);q.add_argument("--manifest",required=True)
 return p
def main(argv=None):
 lock_fd=-1
 try:
  if os.geteuid():raise Error("root_required")
  arguments=parser().parse_args(argv);manifest_path=Path(arguments.manifest)
  if arguments.action in ("quarantine","cleanup") and not manifest_path.exists():
   run_path=re.fullmatch(r"/run/xenoid/proxy/[0-9a-f]{12}/manifest\.json",str(manifest_path))
   state_path=re.fullmatch(r"/var/lib/xenoid/proxy/instances/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/manifest\.json",str(manifest_path))
   if run_path is None and state_path is None:raise Error("unsafe_manifest")
   parent=manifest_path.parent
   if parent.exists():
    metadata=parent.lstat();expected_mode=0o711 if run_path is not None else 0o700
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))!=(0,0,expected_mode) or any(parent.iterdir()):raise Error("ownership_mismatch")
    if arguments.action=="cleanup":parent.rmdir()
   print('{"notPrepared":true,"ok":true}');return 0
  manifest=load_manifest(arguments.manifest);mkdir(LOCK.parent,0o755);lock_fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600);fcntl.flock(lock_fd,fcntl.LOCK_EX)
  if arguments.action=="cleanup":
   if not owner_path(manifest).exists():
    runtime=RUN/manifest["resourceTag"];state=manifest["_state"]
    if (state/"mustBlock").exists():raise Error("ownership_mismatch")
    for directory,mode in ((runtime,0o711),(state,0o700)):
     if not directory.exists():continue
     metadata=directory.lstat()
     if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))!=(0,0,mode) or any(path!=manifest["_path"] for path in directory.iterdir()):raise Error("ownership_mismatch")
    root_file(manifest["_path"],0o600);manifest["_path"].unlink()
    for directory in (runtime,state):
     if directory.exists():directory.rmdir()
    print('{"notPrepared":true,"ok":true}');return 0
   cleanup(manifest,owner(manifest,False));print('{"ok":true}');return 0
  live(manifest,arguments.action in ("check-control","prepare-host","install-control","install-asset","prepare","quarantine"),arguments.action in ("check-control","prepare-host","install-control","install-asset","prepare","quarantine"))
  if arguments.action=="check-control":print(json.dumps({"ok":True,"controlDigest":check_control(manifest)},sort_keys=True,separators=(",",":")));return 0
  if arguments.action=="prepare-host":validate_control();validate_accounts(manifest);install_prerequisites();print('{"ok":true}');return 0
  if arguments.action=="install-control":install_control(manifest);print('{"ok":true}');return 0
  if arguments.action=="install-asset":install_asset(manifest);print('{"ok":true}');return 0
  if arguments.action=="discard-key":discard_key(manifest);print('{"ok":true}');return 0
  ownership=owner(manifest,arguments.action!="status")
  if arguments.action=="service":
   os.close(lock_fd);lock_fd=-1;service_launch(manifest,ownership);raise Error("agent_start_failed")
  if arguments.action=="prepare":prepare(manifest,ownership)
  elif arguments.action=="write-config":write_config(manifest,ownership,sys.stdin.buffer.read(MAX_CONFIG+1))
  elif arguments.action=="apply":apply(manifest,ownership,"candidate",False);apply(manifest,ownership,"candidate",True)
  elif arguments.action=="off":off(manifest,ownership)
  elif arguments.action=="status":print(json.dumps(status(manifest,ownership),sort_keys=True,separators=(",",":")))
  elif arguments.action=="quarantine":quarantine(manifest,ownership)
  if arguments.action!="status":print('{"ok":true}')
  return 0
 except Error as e:print(json.dumps({"ok":False,"error":e.code},separators=(",",":")));return 1
 except Exception:print('{"ok":false,"error":"engine_internal_error"}');return 1
 finally:
  if lock_fd>=0:os.close(lock_fd)
if __name__=="__main__":raise SystemExit(main())
