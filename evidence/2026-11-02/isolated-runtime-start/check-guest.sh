#!/bin/sh
# Read-only VM metadata and credential PATH/ENV NAME existence; never file contents.
set -eu
printf '__HOSTNAME__\n'
hostname
printf '__UNAME__\n'
uname -srm
printf '__MACHINE_ID__\n'
cat /etc/machine-id
printf '__OS_RELEASE__\n'
if [ -r /etc/os-release ]; then
  sed -n '/^ID=/p; /^PRETTY_NAME=/p; /^VERSION_ID=/p' /etc/os-release
fi
printf '__MOUNTS__\n'
findmnt -rn -o SOURCE,TARGET,FSTYPE
printf '__ENV_NAMES_ONLY__\n'
env | sed 's/=.*//' | sort
printf '__AGENT_SOCKET__\n'
if [ -n "${SSH_AUTH_SOCK:-}" ]; then printf 'SSH_AUTH_SOCK_PRESENT\n'; else printf 'SSH_AUTH_SOCK_ABSENT\n'; fi
printf '__USER_CREDENTIAL_PATHS__\n'
for p in "$HOME/.kube/config" "$HOME/.aws/credentials" "$HOME/.aws/config" "$HOME/.docker/config.json" "$HOME/.config/sops/age/keys.txt" "$HOME/.config/age/keys.txt" "$HOME/.ssh/config" /Users /etc/rancher/k3s/k3s.yaml; do
  if [ -e "$p" ]; then printf 'PRESENT %s\n' "$p"; else printf 'ABSENT %s\n' "$p"; fi
done
printf '__ROOT_CREDENTIAL_PATHS__\n'
sudo -n sh -c 'for p in /root/.kube/config /root/.aws/credentials /root/.aws/config /root/.docker/config.json /root/.config/sops/age/keys.txt /root/.config/age/keys.txt /root/.ssh/config; do if [ -e "$p" ]; then printf "PRESENT %s\n" "$p"; else printf "ABSENT %s\n" "$p"; fi; done'
printf '__DOCKERD_ENV_NAMES_ONLY__\n'
sudo -n sh -c 'for p in $(pidof dockerd 2>/dev/null || true); do tr "\000" "\n" < /proc/$p/environ | sed "s/=.*//" | sort; done'
printf '__LOCAL_IP_METADATA__\n'
ip -brief address
