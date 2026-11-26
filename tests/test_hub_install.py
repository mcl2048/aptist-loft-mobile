import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location(
    'hub_provision', pathlib.Path(__file__).resolve().parents[1] / 'hub-install/provision.py'
)
provision = importlib.util.module_from_spec(SPEC) if SPEC else None


class HubProvisionTests(unittest.TestCase):
    def setUp(self):
        if provision is None or SPEC.loader is None:
            self.fail('Hub provisioner is unavailable')
        SPEC.loader.exec_module(provision)

    def test_first_provision_uses_confirmed_pages_domain_and_database(self):
        calls = []

        def send(method, path, payload=None):
            calls.append((method, path, payload))
            replies = {
                ('GET', '/pages/projects/loft-test'): None,
                ('POST', '/pages/projects'): {'name': 'loft-test', 'subdomain': 'loft-test-2ab.pages.dev',
                                             'production_branch': 'main'},
                ('GET', '/d1/database?name=loft-test'): [],
                ('POST', '/d1/database'): {'name': 'loft-test', 'uuid': 'c93c03b6-6ef6-4f5e-bc7f-9b1290e58b8a'},
            }
            return replies[method, path]

        self.assertEqual(provision.prepare(send, 'loft-test'),
                         ('https://loft-test-2ab.pages.dev', 'c93c03b6-6ef6-4f5e-bc7f-9b1290e58b8a'))
        self.assertEqual(calls[1][2], {'name': 'loft-test', 'production_branch': 'main'})

    def test_existing_provision_performs_reads_only(self):
        def send(method, path, payload=None):
            self.assertEqual(method, 'GET')
            if path.startswith('/pages/projects/'):
                return {'name': 'loft-test', 'subdomain': 'loft-test.pages.dev', 'production_branch': 'main'}
            return [{'name': 'loft-test', 'uuid': 'c93c03b6-6ef6-4f5e-bc7f-9b1290e58b8a'}]

        provision.prepare(send, 'loft-test')

    def test_refuses_existing_git_project_before_database_write(self):
        def send(method, path, payload=None):
            self.assertEqual((method, path), ('GET', '/pages/projects/loft-test'))
            return {'name': 'loft-test', 'subdomain': 'loft-test.pages.dev', 'production_branch': 'main',
                    'source': {'type': 'github'}}

        with self.assertRaises(provision.ProvisionError):
            provision.prepare(send, 'loft-test')
