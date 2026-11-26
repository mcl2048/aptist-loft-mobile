"""Provision the named Cloudflare Pages project and D1 database."""
import json
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID


class ProvisionError(Exception):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def check_name(name):
    if not re.fullmatch(r'[a-z][a-z0-9-]{1,36}[a-z0-9]', name):
        raise ProvisionError('Use a lowercase Cloudflare project name of 3–38 characters.')


def cloudflare(account, token):
    if not re.fullmatch(r'[a-f0-9]{32}', account) or not re.fullmatch(r'[\w-]{30,128}', token, re.ASCII):
        raise ProvisionError('Invalid Cloudflare account ID or API token format.')
    opener = build_opener(NoRedirects())
    prefix = f'https://api.cloudflare.com/client/v4/accounts/{account}'

    def send(method, path, payload=None):
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json',
                   'Content-Type': 'application/json', 'User-Agent': 'LOFT Hub installer'}
        request = Request(prefix + path, method=method, headers=headers,
                          data=json.dumps(payload).encode() if payload is not None else None)
        try:
            with opener.open(request, timeout=30) as response:
                result = json.loads(response.read(1024 * 1024))
        except HTTPError as error:
            if error.code == 404 and method == 'GET' and path.startswith(('/pages/projects/', '/workers/scripts/')):
                return None
            raise ProvisionError(f'Cloudflare {method} {path.split("?")[0]} returned HTTP {error.code}.') from None
        except (URLError, TimeoutError, ValueError):
            raise ProvisionError('Cloudflare connection or response failed.') from None
        if not isinstance(result, dict) or result.get('success') is not True or 'result' not in result:
            raise ProvisionError('Cloudflare did not confirm the requested operation.')
        return result['result']

    return send


def prepare(send, name):
    check_name(name)
    project = send('GET', f'/pages/projects/{name}')
    if project is None:
        project = send('POST', '/pages/projects', {'name': name, 'production_branch': 'main'})
    if (not isinstance(project, dict) or project.get('name') != name or project.get('source')
            or project.get('production_branch') != 'main'):
        raise ProvisionError('The Pages project must be a Direct Upload project with production branch main.')
    subdomain = project.get('subdomain')
    if not isinstance(subdomain, str) or not re.fullmatch(r'[a-z0-9-]+\.pages\.dev', subdomain):
        raise ProvisionError('Cloudflare did not provide a Pages hostname.')
    databases = send('GET', f'/d1/database?name={name}')
    if not isinstance(databases, list) or any(not isinstance(row, dict) for row in databases):
        raise ProvisionError('Cloudflare returned an invalid D1 inventory.')
    matches = [row for row in databases if row.get('name') == name]
    if len(matches) > 1:
        raise ProvisionError('More than one D1 database has the requested name.')
    database = matches[0] if matches else send('POST', '/d1/database', {'name': name})
    try:
        database_id = str(UUID(database['uuid']))
        if database['name'] != name:
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ProvisionError('Cloudflare did not confirm the named D1 database.') from None
    return f'https://{subdomain}', database_id


def worker_state(send, name):
    settings = send('GET', f'/workers/scripts/{name}/settings')
    if settings is None:
        return ('new',)
    bindings = settings.get('bindings') if isinstance(settings, dict) else None
    if not isinstance(bindings, list):
        raise ProvisionError('Cloudflare returned invalid Worker settings.')
    variables = {binding.get('name'): binding.get('text') for binding in bindings if isinstance(binding, dict)}
    issuer, client_id = variables.get('PORTAL_ISSUER'), variables.get('PORTAL_CLIENT_ID')
    if (not isinstance(issuer, str) or not re.fullmatch(r'https://[^\s]+/api/idp', issuer)
            or not isinstance(client_id, str) or not re.fullmatch(r'[a-f0-9-]{36}', client_id)):
        raise ProvisionError('An existing Worker does not have the expected LOFT Hub settings.')
    return ('existing', issuer, client_id)


def check_origin(origin):
    if not re.fullmatch(r'https://[a-z0-9-]+\.pages\.dev', origin):
        raise ProvisionError('Invalid Pages origin for the deployment check.')
    request = Request(origin + '/.well-known/loft-app', headers={'User-Agent': 'LOFT Hub installer'})
    opener = build_opener(NoRedirects())
    for attempt in range(6):
        try:
            with opener.open(request, timeout=8) as response:
                data = json.loads(response.read(16 * 1024))
            if (isinstance(data, dict) and data.get('version') == 1 and data.get('product') == 'loft'
                    and data.get('authMode') == 'portal_bff'):
                return
        except (OSError, ValueError):
            pass
        if attempt < 5:
            time.sleep(3)
    raise ProvisionError('The public Pages endpoint did not return the LOFT Hub descriptor.')


def main():
    if len(sys.argv) not in (2, 3, 4):
        raise ProvisionError('Usage: provision.py PROJECT_NAME [worker-state | check ORIGIN]')
    name = sys.argv[1]
    check_name(name)
    if len(sys.argv) == 4 and sys.argv[2] == 'check':
        check_origin(sys.argv[3])
        return
    send = cloudflare(os.environ.get('CLOUDFLARE_ACCOUNT_ID', ''), os.environ.get('CLOUDFLARE_API_TOKEN', ''))
    if len(sys.argv) == 2:
        print(*prepare(send, name))
    elif len(sys.argv) == 3 and sys.argv[2] == 'worker-state':
        print(*worker_state(send, name))
    else:
        raise ProvisionError('Unknown provisioning command.')


if __name__ == '__main__':
    try:
        main()
    except ProvisionError as error:
        sys.exit(str(error))
