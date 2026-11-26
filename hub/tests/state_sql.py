"""Exercise actual Worker SQL with independent writers on a temporary SQLite database."""
from concurrent.futures import ThreadPoolExecutor
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
        with sqlite3.connect(self.path) as connection:
            for migration in sorted((ROOT / 'migrations').glob('*.sql')):
                connection.executescript(migration.read_text())

    def execute(self, name, *arguments):
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(query(name), arguments).fetchone()
            return dict(row) if row else None

    def start(self, index=1, expires=300, limit=64):
        return self.execute('create', f'transaction-{index}', f'state-{index}', 'proof-hash', 'auth-box', expires, 100, limit)

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

    def test_global_rate_window_is_shared_and_rolls_forward(self):
        self.assertIsNotNone(self.execute('rate', 1, 20, 2))
        self.assertIsNotNone(self.execute('rate', 1, 20, 2))
        self.assertIsNone(self.execute('rate', 1, 20, 2))
        self.assertIsNotNone(self.execute('rate', 1, 21, 2))


if __name__ == '__main__':
    unittest.main()
