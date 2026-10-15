"""Install the small user LaunchAgent which supplies Mac/VM resource measurements."""
import argparse
import os
import plistlib
import subprocess
import sys
from pathlib import Path


def install(evidence):
    root = Path(__file__).resolve().parent
    evidence = Path(evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    label = 'local.petclinic.resources'
    path = Path.home() / 'Library' / 'LaunchAgents' / (label + '.plist')
    path.parent.mkdir(exist_ok=True)
    if path.exists():
        (evidence / 'launch-agent-before.plist').write_bytes(path.read_bytes())
    body = {'Label': label, 'ProgramArguments': [sys.executable, str(root / 'host_resources.py')],
            'WorkingDirectory': str(root.parent.parent), 'RunAtLoad': True, 'KeepAlive': True,
            'ThrottleInterval': 30,
            'EnvironmentVariables': {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'},
            'StandardOutPath': str(evidence / 'observer.log'),
            'StandardErrorPath': str(evidence / 'observer-error.log')}
    domain = f'gui/{os.getuid()}'
    subprocess.run(['launchctl', 'bootout', domain + '/' + label], capture_output=True)
    path.write_bytes(plistlib.dumps(body))
    path.chmod(0o600)
    subprocess.run(['launchctl', 'bootstrap', domain, str(path)], check=True)
    subprocess.run(['launchctl', 'kickstart', domain + '/' + label], check=True)
    (evidence / 'installed.plist').write_bytes(path.read_bytes())
    print(str(path))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    install(parser.parse_args().evidence)
