"""Render Wrangler inputs inside the installer's private staging directory."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
from urllib.parse import urlsplit
from uuid import UUID


def main():
    stage, name, origin, database_id = sys.argv[1:]
    work = Path(stage)
    home = Path(__file__).resolve().parent
    hub = home.parent / 'hub'
    issuer = os.environ.get('LOFT_PORTAL_ISSUER', 'https://portal.aptist.net/api/idp')
    client_id = os.environ.get('PORTAL_CLIENT_ID', '')
    client_secret = os.environ.get('PORTAL_CLIENT_SECRET', '')
    encryption_key = os.environ.get('HUB_ENCRYPTION_KEY', '')
    first = os.environ.get('LOFT_FIRST_WORKER_DEPLOY') == '1'
    parsed = urlsplit(issuer)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path != '/api/idp' or issuer != f'https://{parsed.netloc}/api/idp'):
        sys.exit('LOFT_PORTAL_ISSUER must be the exact HTTPS Portal issuer ending in /api/idp.')
    try:
        parsed_client_id = UUID(client_id)
        if parsed_client_id.version != 4 or str(parsed_client_id) != client_id:
            raise ValueError()
    except ValueError:
        sys.exit('PORTAL_CLIENT_ID must contain the registered Portal client UUID.')
    if (first and not client_secret) or (client_secret and not re.fullmatch(r'[A-Za-z0-9_-]{64}', client_secret)):
        sys.exit('Supply the Portal client secret on the first Worker deployment or after rotation.')
    if encryption_key and not re.fullmatch(r'[A-Za-z0-9_-]{43}', encryption_key):
        sys.exit('HUB_ENCRYPTION_KEY must be a base64url encoded 32-byte value.')
    if first and not encryption_key:
        encryption_key = secrets.token_urlsafe(32)

    worker = {
        'name': name, 'main': str(hub / 'build/worker/shim.mjs'),
        'compatibility_date': '2026-11-25', 'workers_dev': False, 'preview_urls': False,
        'compatibility_flags': ['request_signal_passthrough'],
        'observability': {'enabled': False},
        'vars': {'HUB_ORIGIN': origin, 'PORTAL_ISSUER': issuer, 'PORTAL_CLIENT_ID': client_id},
        'secrets': {'required': ['PORTAL_CLIENT_SECRET', 'HUB_ENCRYPTION_KEY']},
        'd1_databases': [{'binding': 'DB', 'database_name': name, 'database_id': database_id,
                          'migrations_dir': './migrations'}],
        'triggers': {'crons': ['*/5 * * * *']},
    }
    pages = {
        'name': name, 'pages_build_output_dir': './pages', 'compatibility_date': '2026-11-25',
        'services': [{'binding': 'HUB', 'service': name}],
    }
    (work / 'worker.json').write_text(json.dumps(worker) + '\n')
    (work / 'wrangler.json').write_text(json.dumps(pages) + '\n')
    shutil.copytree(home / 'pages', work / 'pages')
    shutil.copytree(hub / 'migrations', work / 'migrations')
    values = {name: value for name, value in {'PORTAL_CLIENT_SECRET': client_secret,
                                              'HUB_ENCRYPTION_KEY': encryption_key}.items() if value}
    if values:
        (work / 'secrets.json').write_text(json.dumps(values) + '\n')


if __name__ == '__main__':
    main()
