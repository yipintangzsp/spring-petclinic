#!/bin/sh
# Prepared, not executed: intentionally restores the pre-existing DNS failure.
# Never uses the default profile or a remote production host.
set -eu
/opt/homebrew/bin/colima ssh -p security-test -- sudo -n python3 - <<'PY'
import hashlib
import os
import socket
import subprocess

assert socket.gethostname() == "security-test"
assert open("/etc/machine-id").read().strip() == "a093ffaa4d594b5298d97235be9e69ae"
path = "/etc/resolv.conf"
backup = "/var/tmp/security-test-dns-20261102/resolv.conf.before"
assert not os.path.islink(path)
assert hashlib.sha256(open(path, "rb").read()).hexdigest() == "a14900c18776adf824748ca5bf4410bdf00eb5e7a6afbb0f2de1639a237c0be6"
assert os.path.islink(backup)
assert os.readlink(backup) == "../run/systemd/resolve/stub-resolv.conf"
temp = "/var/tmp/security-test-dns-20261102/resolv.conf.rollback"
assert not os.path.lexists(temp)
subprocess.run(["cp", "-a", backup, temp], check=True)
os.replace(temp, path)
assert os.readlink(path) == "../run/systemd/resolve/stub-resolv.conf"
print("Original resolver symlink restored; original missing-target DNS failure is expected.")
PY
