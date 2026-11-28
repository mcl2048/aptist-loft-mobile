"""Exercise actual Worker SQL with independent writers on a temporary SQLite database."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def query(name):
    return (ROOT / 'src/sql' / (name + '.sql')).read_text()


class HubDatabase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'hub.db'
        with closing(sqlite3.connect(self.path)) as connection, connection:
            for migration in sorted((ROOT / 'migrations').glob('*.sql')):
                connection.executescript(migration.read_text())

    def execute(self, name, *arguments):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(query(name), arguments).fetchone()
            return dict(row) if row else None

    def start(self, index=1, expires=300, limit=64):
        return self.execute('create', f'transaction-{index}', f'state-{index}', 'proof-hash', 'auth-box', expires, 100, limit, None)

    def claim(self, index=1, at=110):
        return self.execute('claim', f'state-{index}', at)

    def complete(self, index=1, proof='proof-hash', at=120):
        return self.execute('complete', f'transaction-{index}', proof, at)

    def test_global_admission_counts_concurrent_unexpired_transactions(self):
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(lambda i: self.start(i, limit=3), range(10)))
        self.assertEqual(sum(result is not None for result in results), 3)
        self.assertIsNone(self.start(11, limit=3))

    def test_callback_is_claimed_once_and_completion_recovers_same_session(self):
        self.assertIsNotNone(self.start())
        self.assertIsNone(self.complete())
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(lambda _: self.claim(), range(10)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertIsNone(self.complete())
        self.execute('finish', 'transaction-1', 'session-hash', 'encrypted-session', 350, 119)
        self.assertIsNone(self.complete(proof='wrong-hash'))
        self.assertIsNone(self.execute('session', 'session-hash', 119))
        first = self.complete()
        self.assertEqual(first['session_box'], 'encrypted-session')
        self.assertEqual(self.complete(at=121), first)
        self.assertIsNone(self.complete(at=300))
        self.assertIsNotNone(self.execute('session', 'session-hash', 300))
        self.assertIsNone(self.execute('session', 'session-hash', 350))

    def test_cancel_of_claimed_transaction_prevents_late_session_publication(self):
        self.start()
        self.claim()
        self.execute('cancel', 'transaction-1', 'proof-hash')
        self.execute('finish', 'transaction-1', 'session-hash', 'encrypted-session', 350, 119)
        self.assertIsNone(self.complete())
        self.assertIsNone(self.execute('session', 'session-hash', 120))

    def durable_fixture(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("INSERT INTO hub_device_session (session_hash, owner_hash, identity_box) VALUES ('hash-a', 'owner-a', 'box-a')")
            connection.execute("INSERT INTO hub_device_session (session_hash, owner_hash, identity_box) VALUES ('hash-b', 'owner-b', 'box-b')")
            connection.execute("INSERT INTO hub_device_session (session_hash, owner_hash, identity_box) VALUES ('hash-a2', 'owner-a', 'box-a')")

    def test_vault_cas_is_atomic_and_uses_session_owner(self):
        self.durable_fixture()
        def replace(i):
            return self.execute('vault_write', 'hash-a', 'v' * 43, 0, 'solar-ciphertext-fixture-' + str(i), 8)
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(replace, range(10)))
        self.assertEqual(sum(value is not None for value in results), 1)
        first = self.execute('vault_read', 'hash-a2', 'v' * 43)
        self.assertEqual(first['revision'], 1)
        self.assertIsNone(self.execute('vault_read', 'hash-b', 'v' * 43))
        self.assertIsNone(self.execute('vault_write', 'hash-b', 'v' * 43, 1, 'foreign', 8))
        self.assertEqual(self.execute('vault_write', 'hash-a2', 'v' * 43, 1, 'replacement-fixture-ciphertext', 8), {'revision': 2})
        self.assertEqual(self.execute('vault_read', 'hash-a', 'v' * 43)['ciphertext'], 'replacement-fixture-ciphertext')

    def test_vault_caps_owner_rows_and_survives_revoked_session(self):
        self.durable_fixture()
        self.assertIsNotNone(self.execute('vault_write', 'hash-a', 'f' * 43, 0, 'synthetic-ciphertext-fixture', 1))
        self.assertIsNone(self.execute('vault_write', 'hash-a', 's' * 43, 0, 'synthetic-ciphertext-fixture', 1))
        self.assertIsNotNone(self.execute('vault_write', 'hash-b', 's' * 43, 0, 'different-ciphertext-fixture', 1))
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DELETE FROM hub_device_session WHERE session_hash = 'hash-a'")
        self.assertIsNone(self.execute('vault_write', 'hash-a', 'f' * 43, 1, 'revoked', 1))
        self.assertIsNone(self.execute('vault_read', 'hash-a', 'f' * 43))
        self.assertEqual(self.execute('vault_read', 'hash-a2', 'f' * 43)['ciphertext'], 'synthetic-ciphertext-fixture')

    def test_global_rate_window_is_shared_and_rolls_forward(self):
        self.assertIsNotNone(self.execute('rate', 1, 20, 2))
        self.assertIsNotNone(self.execute('rate', 1, 20, 2))
        self.assertIsNone(self.execute('rate', 1, 20, 2))
        self.assertIsNotNone(self.execute('rate', 1, 21, 2))

    def test_notes_revision_cas_and_conditional_reads_are_owner_scoped(self):
        self.durable_fixture()
        def create(i):
            return self.execute('notes_write', 'hash-a', 0, 'notes-ciphertext-fixture-' + str(i), None)
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(create, range(10)))
        self.assertEqual(results.count({'revision': 1}), 1)
        self.assertIsNone(self.execute('notes_read', 'not-enrolled', 0))
        self.assertEqual(self.execute('notes_read', 'hash-b', 1), {'revision': None, 'ciphertext': None, 'key_epoch': None})
        self.assertEqual(self.execute('notes_read', 'hash-a2', 1), {'revision': 1, 'ciphertext': None, 'key_epoch': None})
        self.assertIsNone(self.execute('notes_write', 'hash-b', 1, 'foreign-ciphertext-fixture', None))
        self.assertIsNone(self.execute('notes_write', 'not-enrolled', 1, 'foreign-ciphertext-fixture', None))
        self.assertEqual(self.execute('notes_write', 'hash-a2', 1, 'replacement-ciphertext-fixture', None), {'revision': 2})
        self.assertEqual(self.execute('notes_read', 'hash-a', 1), {'revision': 2, 'ciphertext': 'replacement-ciphertext-fixture', 'key_epoch': None})
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DELETE FROM hub_device_session WHERE session_hash = 'hash-a'")
        self.assertIsNone(self.execute('notes_write', 'hash-a', 2, 'revoked-ciphertext-fixture', None))
        self.assertIsNone(self.execute('notes_read', 'hash-a', 2))

    def test_notes_reset_replaces_pre_migration_row_and_replay_cannot_replace_new_write(self):
        self.durable_fixture()
        epoch = 'a' * 22
        fingerprint = 'b' * 43
        with closing(sqlite3.connect(self.path)) as connection, connection:
            # An upgraded deployment can already have a 0.1.7 dataset.
            connection.execute("INSERT INTO hub_notes (owner_hash, revision, ciphertext) VALUES (?, ?, ?)",
                               ('owner-a', 9, 'pre-migration-ciphertext-fixture'))
        self.assertIsNone(self.execute('notes_reset', 'hash-b', 9, 'replacement-ciphertext-fixture', epoch, fingerprint))
        self.assertEqual(self.execute('notes_reset', 'hash-a', 9, 'replacement-ciphertext-fixture', epoch, fingerprint),
                         {'revision': 10})
        self.assertIsNone(self.execute('notes_write', 'hash-a2', 10, 'legacy-ciphertext-fixture', None))
        self.assertEqual(self.execute('notes_write', 'hash-a2', 10, 'peer-update-ciphertext-fixture', epoch), {'revision': 11})
        self.assertIsNone(self.execute('notes_reset', 'hash-a', 9, 'replacement-ciphertext-fixture', epoch, fingerprint))
        self.assertEqual(self.execute('notes_reset_receipt', 'hash-a2', epoch, 9, fingerprint), {'reset_revision': 10})
        self.assertIsNone(self.execute('notes_reset_receipt', 'hash-b', epoch, 9, fingerprint))
        self.assertIsNone(self.execute('notes_reset_receipt', 'hash-a', epoch, 9, 'c' * 43))
        self.assertEqual(self.execute('notes_read', 'hash-a', 10),
                         {'revision': 11, 'ciphertext': 'peer-update-ciphertext-fixture', 'key_epoch': epoch})


if __name__ == '__main__':
    unittest.main()
