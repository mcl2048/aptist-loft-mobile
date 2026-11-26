#!/usr/bin/env python3
"""Copy pinned production sources only; never import deployment configuration."""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / 'third_party/SOURCE-LOCK.json').exists():
    raise SystemExit('existing owned source snapshot: update source pins and mobile patches through a reviewed refresh, not an overwrite')
GATEWAY = Path('/home/coder/Loft-Gateway')
PIN = '98644864d2426627cd151a0561e5035e46f6b79c'
PRODUCTION_SUFFIXES = {'.go', '.s', '.S', '.h', '.c', '.proto'}
MODULE_FILES = {'go.mod', 'go.sum', 'LICENSE', 'LICENSE.md', 'COPYING', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'UPSTREAM-SHA256SUMS', 'README.loft.md'}
COMPONENTS = (
    'modules/hyrakenx', 'pkg/hyrakenpro', 'pkg/hyrakenquic',
    'modules/firewall/hydra', 'pkg/trafficprofile',
    'GhostX-core-main/transport/beastprofile',
)

def production_file(relative):
    path = Path(relative)
    if any(part in {'testdata', 'integrationtests', '.git'} for part in path.parts):
        return False
    return not path.name.endswith('_test.go') and (path.suffix in PRODUCTION_SUFFIXES or path.name in MODULE_FILES)

receipts = []
for component in COMPONENTS:
    files = subprocess.run(['git', '-C', str(GATEWAY), 'ls-tree', '-r', '--name-only', PIN, '--', component], check=True, text=True, stdout=subprocess.PIPE).stdout.splitlines()
    for relative in files:
        if not production_file(relative):
            continue
        data = subprocess.run(['git', '-C', str(GATEWAY), 'show', PIN + ':' + relative], check=True, stdout=subprocess.PIPE).stdout
        if (GATEWAY / relative).read_bytes() != data:
            raise SystemExit('Source differs from reviewed pin: ' + relative)
        destination = ROOT / 'third_party/Loft-Gateway' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        receipts.append({'source': relative, 'destination': str(destination.relative_to(ROOT)), 'source_sha256': hashlib.sha256(data).hexdigest()})

gateway_notice = (GATEWAY / 'GhostX-core-main/LICENSE').read_bytes()
destination = ROOT / 'third_party/Loft-Gateway/GhostX-core-main/LICENSE'
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_bytes(gateway_notice)

SING_TUN_VERSION = 'v0.9.6-0.20260924001923-ddaa4ca25e3b'
SING_TUN = Path('/home/coder/go/pkg/mod/github.com/sagernet/sing-tun@' + SING_TUN_VERSION)
for source in sorted(SING_TUN.rglob('*')):
    if not source.is_file() or not production_file(str(source.relative_to(SING_TUN))):
        continue
    data = source.read_bytes()
    destination = ROOT / 'third_party/sing-tun' / source.relative_to(SING_TUN)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    receipts.append({'source': 'github.com/sagernet/sing-tun@' + SING_TUN_VERSION + '/' + str(source.relative_to(SING_TUN)), 'destination': str(destination.relative_to(ROOT)), 'source_sha256': hashlib.sha256(data).hexdigest()})

manifest = {'schema_version': 1, 'gateway_commit': PIN, 'source_scope': 'Pinned production Go/native sources and module/license files; deployment configurations, test credentials and private guides excluded.', 'sing_tun_version': SING_TUN_VERSION, 'sing_version': 'v0.9.6-0.20260922013354-87c33f17688f', 'gvisor_version': 'v0.0.0-20260727.0-sing-box-mod.1', 'files': receipts, 'mobile_patches': []}
(ROOT / 'third_party/SOURCE-LOCK.json').write_text(json.dumps(manifest, indent=2) + '\n')
print('Pinned production source snapshots:', len(receipts), 'files; no deployment configuration copied.')
