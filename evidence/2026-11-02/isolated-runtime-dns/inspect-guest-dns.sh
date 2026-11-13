#!/bin/sh
# Only resolver/service/route metadata in the dedicated VM, never credentials.
set -u
printf '__IDENTITY__\n'
hostname
uname -srm
printf '__RESOLV_PATH__\n'
ls -ld /etc/resolv.conf /run/systemd/resolve /run/systemd/resolve/resolv.conf /run/systemd/resolve/stub-resolv.conf 2>&1 || true
readlink /etc/resolv.conf || true
printf '__RESOLV_CONTENT__\n'
cat /etc/resolv.conf 2>&1 || true
printf '__RESOLVER_SERVICE__\n'
systemctl is-active systemd-resolved 2>&1 || true
systemctl is-enabled systemd-resolved 2>&1 || true
systemctl show systemd-resolved -p LoadState -p ActiveState -p SubState -p FragmentPath 2>&1 || true
printf '__RESOLVECTL__\n'
resolvectl status --no-pager 2>&1 || true
printf '__RESOLVED_CONFIG__\n'
if [ -f /etc/systemd/resolved.conf ]; then sha256sum /etc/systemd/resolved.conf; sed -n '/^[^#;[:space:]]/p' /etc/systemd/resolved.conf; fi
printf '__DNS_LISTENERS__\n'
ss -uln | awk 'NR==1 || /:53[[:space:]]/'
printf '__ROUTE__\n'
ip route
printf '__VM_PUBLIC_LOOKUP__\n'
timeout 12 getent ahostsv4 registry-1.docker.io; printf 'GETENT_EXIT=%s\n' "$?"
printf '__TOOLS__\n'
for p in curl resolvectl dig nslookup; do command -v "$p" || true; done
