"""Only synthetic fixtures in an ephemeral container; never run on a host."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path('/lab')

def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **kw)

def checked(args, **kw):
    value = run(args, **kw)
    if value.returncode:
        raise RuntimeError(f'{args[0]} failed: {value.stderr[-1500:]}')
    return value.stdout

def emit(value):
    print(json.dumps(value))

def ssh_setup():
    checked(['useradd', '-m', '-s', '/bin/sh', 'labadmin'])
    # Unlock only this synthetic account. Password auth remains denied by the template.
    checked(['chpasswd'], input='labadmin:PUBLIC_SYNTHETIC_LAB_ONLY\n')
    checked(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/lab/good'])
    checked(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/lab/wrong'])
    checked(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/lab/host'])
    pub = Path('/lab/good.pub').read_bytes()
    for home in ['/home/labadmin', '/root']:
        folder = Path(home) / '.ssh'
        folder.mkdir(mode=0o700, exist_ok=True)
        (folder / 'authorized_keys').write_bytes(pub)
        (folder / 'authorized_keys').chmod(0o600)
    checked(['chown', '-R', 'labadmin:labadmin', '/home/labadmin/.ssh'])
    Path('/run/sshd').mkdir(exist_ok=True)
    template = (ROOT / 'infra/ssh/00-security.conf.template').read_text()
    if template.count('@@ADMIN_USER@@') != 1:
        raise RuntimeError('SSH template marker count changed')
    config = template.replace('@@ADMIN_USER@@', 'labadmin')
    config += '\nPort 2222\nListenAddress 0.0.0.0\nHostKey /lab/host\nUsePAM no\nPidFile /lab/sshd.pid\n'
    Path('/lab/sshd.conf').write_text(config)
    checked(['/usr/sbin/sshd', '-t', '-f', '/lab/sshd.conf'])
    checked(['/usr/sbin/sshd', '-f', '/lab/sshd.conf'])
    effective = checked(['/usr/sbin/sshd', '-T', '-f', '/lab/sshd.conf'])
    emit({'ok': True, 'effective': effective.splitlines(), 'pid': int(Path('/lab/sshd.pid').read_text())})

def ssh_probe(ip):
    Path('/lab/known_hosts').write_text(f'[{ip}]:2222 ' + Path('/lab/host.pub').read_text())
    common = ['ssh', '-F', '/dev/null', '-p', '2222', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/lab/known_hosts', '-o', 'ConnectTimeout=4', '-o', 'IdentitiesOnly=yes']
    good = run(common + ['-o', 'BatchMode=yes', '-i', '/lab/good', f'labadmin@{ip}', 'printf LAB_KEY_OK'])
    wrong = run(common + ['-o', 'BatchMode=yes', '-i', '/lab/wrong', f'labadmin@{ip}', 'true'])
    root = run(common + ['-o', 'BatchMode=yes', '-i', '/lab/good', f'root@{ip}', 'true'])
    ask = Path('/lab/askpass')
    ask.write_text('#!/bin/sh\nprintf PUBLIC_SYNTHETIC_LAB_ONLY\n')
    ask.chmod(0o700)
    env = dict(os.environ, SSH_ASKPASS=str(ask), SSH_ASKPASS_REQUIRE='force', DISPLAY='synthetic:0')
    password = run(common + ['-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password', f'labadmin@{ip}', 'true'], env=env, stdin=subprocess.DEVNULL)
    value = {'keySuccess': good.returncode == 0 and good.stdout == 'LAB_KEY_OK', 'wrongKeyDenied': wrong.returncode == 255 and 'Permission denied' in wrong.stderr, 'rootDenied': root.returncode == 255 and 'Permission denied' in root.stderr, 'passwordDenied': password.returncode == 255 and 'Permission denied' in password.stderr}
    emit({'ok': all(value.values()), **value})

def tcp_probe(ip, port):
    try:
        with socket.create_connection((ip, int(port)), 2):
            emit({'connected': True})
    except (OSError, TimeoutError):
        emit({'connected': False})

def firewall(ip):
    policy = {'schema_version': 1, 'ssh_port': 2222, 'admin_cidrs': [ip + '/32'], 'proxy_cidrs': [ip + '/32']}
    Path('/lab/policy.json').write_text(json.dumps(policy))
    checked(['/usr/bin/python3', '/lab/infra/firewall/render.py', '--policy', '/lab/policy.json', '--output', '/lab/firewall.nft'])
    checked(['nft', '-c', '-f', '/lab/firewall.nft'])
    checked(['nft', '-f', '/lab/firewall.nft'])
    emit({'ok': True, 'rules': checked(['nft', '-j', 'list', 'table', 'inet', 'amqic_origin_guard'])})

def wg_setup(peer_ip, public_key, side):
    if public_key == '-':
        create = run(['ip', 'link', 'add', 'wgtest', 'type', 'wireguard'])
        if create.returncode:
            emit({'status': 'unsupported', 'reason': create.stderr.strip()})
            return
        private = checked(['wg', 'genkey'])
        Path('/lab/wg-private').write_text(private)
        Path('/lab/wg-private').chmod(0o600)
    else:
        private = Path('/lab/wg-private').read_text()
    public = checked(['wg', 'pubkey'], input=private).strip()
    if public_key != '-':
        checked(['wg', 'set', 'wgtest', 'listen-port', '51820', 'private-key', '/lab/wg-private', 'peer', public_key, 'allowed-ips', f'10.77.0.{3-int(side)}/32', 'endpoint', peer_ip + ':51820'])
        checked(['ip', 'address', 'add', f'10.77.0.{side}/24', 'dev', 'wgtest'])
        checked(['ip', 'link', 'set', 'wgtest', 'up'])
    emit({'status': 'ready', 'publicKey': public})

def complements():
    results = []
    for python in ['/usr/bin/python3', '/usr/local/bin/python3']:
        version = checked([python, '--version']).strip()
        for test in ['test_terminal_input.py', 'test_operations.py']:
            result = run([python, '-B', '/lab/scripts/' + test])
            # unittest may legitimately skip platform-only Windows cases; PTY must run.
            results.append({'python': version, 'test': test, 'ok': result.returncode == 0 and 'Ran ' in result.stderr and 'OK' in result.stderr and not (test == 'test_terminal_input.py' and 'skipped=' in result.stderr), 'summary': result.stderr[-1000:]})
    emit({'ok': all(r['ok'] for r in results), 'tests': results})

def artifacts():
    source = Path('/lab/synthetic.c')
    source.write_text('static int internal_example(int x){return x+1;}\nint main(void){return internal_example(0)-1;}\n')
    checked(['gcc', '-g', '-O0', str(source), '-o', '/lab/synthetic'])
    checked(['objcopy', '--only-keep-debug', '/lab/synthetic', '/lab/synthetic.debug'])
    checked(['strip', '--strip-debug', '/lab/synthetic'])
    checked(['objcopy', '--add-gnu-debuglink=/lab/synthetic.debug', '/lab/synthetic'])
    sections = checked(['readelf', '-S', '/lab/synthetic'])
    debug_sections = checked(['readelf', '-S', '/lab/synthetic.debug'])
    symbols = {'ok': '.debug_info' not in sections and '.debug_info' in debug_sections and '.gnu_debuglink' in sections and run(['/lab/synthetic']).returncode == 0}
    password = 'PUBLIC_SYNTHETIC_LAB_PASSWORD\n'
    created = run(['keepassxc-cli', 'db-create', '-p', '/lab/synthetic.kdbx'], input=password * 2)
    opened = run(['keepassxc-cli', 'db-info', '/lab/synthetic.kdbx'], input=password)
    rejected = run(['keepassxc-cli', 'db-info', '/lab/synthetic.kdbx'], input='PUBLIC_WRONG_PASSWORD\n')
    vault = {'ok': created.returncode == 0 and opened.returncode == 0 and rejected.returncode != 0, 'created': created.returncode == 0, 'correctPasswordOpened': opened.returncode == 0, 'wrongPasswordDenied': rejected.returncode != 0}
    emit({'ok': symbols['ok'] and vault['ok'], 'symbolSeparation': symbols, 'syntheticKeePass': vault})

if __name__ == '__main__':
    commands = {'ssh-setup': ssh_setup, 'ssh-probe': ssh_probe, 'tcp': tcp_probe, 'firewall': firewall, 'wg-setup': wg_setup, 'complements': complements, 'artifacts': artifacts}
    commands[sys.argv[1]](*sys.argv[2:])
