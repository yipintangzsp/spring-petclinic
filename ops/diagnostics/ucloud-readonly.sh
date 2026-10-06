#!/usr/bin/env bash
# Run on the existing ucloud-worker console/SSH. Read-only; never prints K3S_TOKEN.
set -u
export TZ=Asia/Shanghai
redact() { sed -E 's/((K3S_TOKEN|--token|password|Authorization)[[:space:]:=]+)[^[:space:]]+/\1[REDACTED]/Ig'; }
section() { printf '\n===== %s =====\n' "$1"; }
section identity
hostname; date -Iseconds; uptime
section resources
free -h; df -h; df -i; vmstat 1 10
for resource in memory io cpu; do cat "/proc/pressure/$resource" 2>/dev/null || true; done
section processes
ps -eo pid,ppid,comm,rss,%cpu,%mem --sort=-rss | head -30
section agent
systemctl show k3s-agent -p ActiveState -p SubState -p MainPID -p NRestarts -p MemoryCurrent -p MemoryMax -p FragmentPath
# Unit configuration is redacted; the environment file is not printed.
systemctl cat k3s-agent 2>&1 | redact
section endpoint
endpoint=$(python3 - <<'PY'
import pathlib,urllib.parse
for name in ['/etc/systemd/system/k3s-agent.service.env','/etc/default/k3s-agent','/etc/sysconfig/k3s-agent']:
 p=pathlib.Path(name)
 if not p.exists():continue
 for line in p.read_text().splitlines():
  if line.strip().startswith('K3S_URL='):
   u=urllib.parse.urlsplit(line.split('=',1)[1].strip().strip(chr(34)+chr(39)))
   if u.hostname:
    host='['+u.hostname+']' if ':' in u.hostname else u.hostname
    print(urllib.parse.urlunsplit((u.scheme,host+(':'+str(u.port) if u.port else ''),u.path,'','')))
PY
)
printf 'K3S_URL=%s\n' "$endpoint"
section routing
ip addr; ip route; ip rule; ss -s; ip -s link
if command -v wg >/dev/null; then wg show all latest-handshakes; wg show all allowed-ips; fi
# Do not output a WireGuard dump/private key or k3s agent client credentials.
section agent_window
journalctl -u k3s-agent --since '2026-10-06 20:10:00' --until '2026-10-06 20:40:00' --no-pager -o short-iso | grep -Ei 'error|timeout|configmap|secret|reflector|watch|list|apiserver|lease|remotedialer|websocket|connection|EOF|deadline|transport|memory|oom|evict|pressure' | redact || true
section agent_recent
journalctl -u k3s-agent --since '-10 min' --no-pager -o short-iso | grep -Ei 'error|timeout|configmap|secret|reflector|watch|list|apiserver|lease|remotedialer|websocket|connection|EOF|deadline|transport|memory|oom|evict|pressure' | redact || true
section kernel
journalctl -k --since '2026-10-06 20:10:00' --no-pager -o short-iso | grep -Ei 'oom|killed process|hung|blocked|I/O error|reset|network|conntrack|memory' | redact || true
section conntrack
for p in nf_conntrack_count nf_conntrack_max; do printf '%s=' "$p"; cat "/proc/sys/net/netfilter/$p" 2>/dev/null || true; done
if command -v conntrack >/dev/null; then conntrack -S; fi
section api_transport
if [ -n "$endpoint" ]; then
 export PETCLINIC_DIAG_ENDPOINT="$endpoint"
 python3 - <<'PY'
import os,urllib.parse,socket,ssl,time,datetime
u=urllib.parse.urlsplit(os.environ['PETCLINIC_DIAG_ENDPOINT']);host=u.hostname;port=u.port or (443 if u.scheme=='https' else 80)
for i in range(30):
 begin=time.monotonic();result='TCP_OK'
 try:
  with socket.create_connection((host,port),timeout=2) as s:
   if u.scheme=='https':
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    with ctx.wrap_socket(s,server_hostname=host):result='TCP_TLS_OK'
 except Exception as e:result=type(e).__name__+': '+str(e)
 print(datetime.datetime.now().isoformat(),host,port,result,round(time.monotonic()-begin,3),flush=True)
 time.sleep(2)
PY
fi
