"""Behavioral tests for owned-byte source verification in a clean checkout."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("verify_owned_sources.py")


class OwnedSourceVerification(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.party = self.root / "third_party"
        self.party.mkdir()
        self.file = self.party / "production.go"
        self.file.write_bytes(b"owned production bytes\n")
        self.addition = self.party / "mobile.go"
        self.addition.write_bytes(b"bounded mobile adapter\n")
        self.manifest = {
            "schema_version": 1,
            "gateway_commit": "98644864d2426627cd151a0561e5035e46f6b79c",
            "files": [
                {"source_kind": "source_snapshot", "source": "/unavailable/provenance/production.go", "destination": "third_party/production.go", "source_sha256": hashlib.sha256(b"upstream production bytes\n").hexdigest(), "owned_sha256": hashlib.sha256(self.file.read_bytes()).hexdigest()},
                {"source_kind": "mobile_addition", "source": "LOFT mobile adapter", "destination": "third_party/mobile.go", "source_sha256": None, "owned_sha256": hashlib.sha256(self.addition.read_bytes()).hexdigest()},
            ],
            "mobile_patches": [{"id": "bounded_adapter", "files": ["third_party/production.go", "third_party/mobile.go"], "reason": "Protect sockets and bound mobile ownership."}],
        }
        self.save()

    def save(self):
        (self.party / "SOURCE-LOCK.json").write_text(json.dumps(self.manifest))

    def run_verifier(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root)], capture_output=True, text=True)
        return result.returncode, result.stdout + result.stderr

    def test_valid_owned_tree_does_not_read_unavailable_provenance_paths(self):
        status, output = self.run_verifier()
        self.assertEqual(status, 0, output)
        receipt = json.loads(output)
        self.assertEqual(receipt["verified_files"], 2)
        self.assertEqual(receipt["patched_files"], 2)

    def test_changed_owned_bytes_are_rejected(self):
        self.file.write_bytes(b"unreviewed alteration\n")
        status, output = self.run_verifier()
        self.assertNotEqual(status, 0)
        self.assertIn("loft.sources.digest_mismatch", output)

    def test_unrecorded_owned_file_is_rejected(self):
        (self.party / "unreviewed.go").write_bytes(b"unreviewed source\n")
        status, output = self.run_verifier()
        self.assertNotEqual(status, 0)
        self.assertIn("loft.sources.unrecorded_file", output)

    def test_modified_source_needs_an_explicit_patch_record(self):
        self.manifest["mobile_patches"] = []
        self.save()
        status, output = self.run_verifier()
        self.assertNotEqual(status, 0)
        self.assertIn("loft.sources.unrecorded_patch", output)

    def test_destination_cannot_traverse_outside_owned_tree(self):
        self.manifest["files"][0]["destination"] = "third_party/../../outside.go"
        self.save()
        status, output = self.run_verifier()
        self.assertNotEqual(status, 0)
        self.assertIn("loft.sources.unsafe_destination", output)

    def test_owned_symlink_cannot_substitute_external_source(self):
        outside = self.root / "outside.go"
        outside.write_bytes(self.file.read_bytes())
        self.file.unlink()
        self.file.symlink_to(outside)
        status, output = self.run_verifier()
        self.assertNotEqual(status, 0)
        self.assertIn("loft.sources.unsafe_destination", output)


if __name__ == "__main__":
    unittest.main()
