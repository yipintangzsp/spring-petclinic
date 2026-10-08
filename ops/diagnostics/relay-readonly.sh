#!/usr/bin/env bash
# Run on the existing Alibaba relay console as root. No configuration changes.
set -u
date -u -Is
hostname
systemctl status ssh sshd k3s-agent --no-pager -l
ss -ltnp '( sport = :22 )'
ss -s
ip -s link
ip route
free -h
df -h /
journalctl --utc -u ssh -u sshd --since '2026-10-07 09:15:00 UTC' --until '2026-10-07 09:40:00 UTC' --no-pager
journalctl --utc -u ssh -u sshd -n 100 --no-pager
journalctl --utc -u k3s-agent -n 60 --no-pager
dmesg -T | grep -Ei 'oom|conntrack|drop|reset|timeout|error' | tail -60
