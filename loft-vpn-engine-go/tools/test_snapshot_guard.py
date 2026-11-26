"""A source-maintenance run cannot silently overwrite reviewed mobile patches."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class SnapshotGuard(unittest.TestCase):
    def test_existing_owned_lock_prevents_source_resnapshot_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tools").mkdir()
            script = root / "tools" / "snapshot_sources.py"
            shutil.copyfile(Path(__file__).with_name("snapshot_sources.py"), script)
            party = root / "third_party"
            party.mkdir()
            lock = party / "SOURCE-LOCK.json"
            lock.write_bytes(b'{"mobile_patches":["reviewed-owned-patch"]}\n')
            mobile = party / "Loft-Gateway/modules/hyrakenx/quic.go"
            mobile.parent.mkdir(parents=True)
            mobile.write_bytes(b"reviewed protected-socket mobile bytes\n")
            result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("existing owned source snapshot", result.stdout + result.stderr)
            self.assertEqual(lock.read_bytes(), b'{"mobile_patches":["reviewed-owned-patch"]}\n')
            self.assertEqual(mobile.read_bytes(), b"reviewed protected-socket mobile bytes\n")


if __name__ == "__main__":
    unittest.main()
