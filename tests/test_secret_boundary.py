"""Catch real delivery leakage rather than matching implementation source text."""
import importlib.util
import base64
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/verify_secrets.py"
spec = importlib.util.spec_from_file_location("verify_secrets", path)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class SecretBoundaryTests(unittest.TestCase):
    def test_extracts_task_token_without_endpoint_or_public_pin(self):
        token = "github_pat_" + "syntheticOnly0123456789" * 3
        self.assertEqual(scanner.extract_credentials("[Github Token] " + token), [token.encode()])

    def test_extracts_encoded_seed_and_private_key_from_runtime_node(self):
        seed = "private%2Fseed012345678901234567890"
        key = "privateKeyMaterial01234567890123456789"
        result = scanner.extract_credentials("hyrakenx://" + seed + "@node.example.test:443?key=" + key)
        self.assertIn(b"private/seed012345678901234567890", result)
        self.assertIn(key.encode(), result)
        self.assertNotIn(b"node.example.test", result)

    def test_detects_secret_embedded_in_binary_output(self):
        secret = b"private-node-material0123456789"
        self.assertTrue(scanner.contains_credential(b"\x00ELF\xff" + secret + b"\x00", [secret]))

    def test_clean_binary_and_common_short_values_do_not_match(self):
        self.assertFalse(scanner.contains_credential(b"normal public code 443", [b"443", b"x"]))

    def test_decoded_private_key_is_detected_when_the_uri_stored_base64_pem(self):
        der = b"privateKeyDER01234567890123456789"
        pem = "-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PRIVATE KEY-----\n"
        encoded = base64.b64encode(pem.encode()).decode()
        values = scanner.extract_credentials("hyrakenx://seed01234567890123456789@node.example.test:443?key=" + encoded)
        self.assertIn(pem.encode(), values)
        self.assertIn(der, values)

    def test_known_pat_format_is_blocked_without_local_private_inputs(self):
        token = ("ghp_" + "syntheticPrivateOnly0123456789").encode()
        self.assertTrue(scanner.contains_credential(b"config=" + token, []))

    def test_a_pat_split_across_read_chunks_is_still_detected(self):
        token = ("ghp_" + "syntheticPrivateOnly0123456789").encode()
        data = b"a" * 65530 + token
        self.assertTrue(scanner.scan_stream(io.BytesIO(data), len(data), []))


class DeliveryScannerTests(unittest.TestCase):
    """Execute the delivered CLI in a real isolated index with synthetic inputs."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "scripts").mkdir()
        (self.root / "Prompt").mkdir()
        self.program = self.root / "scripts/verify_secrets.py"
        shutil.copyfile(path, self.program)
        self.token = "ghp_" + "syntheticPrivateOnly0123456789" * 2
        (self.root / "Prompt/Task-Now.txt").write_text("[Github Token] " + self.token + "\n")
        self.git("init", "-q")

    def git(self, *arguments):
        return subprocess.run(["git", *arguments], cwd=self.root, check=True, capture_output=True)

    def run_scanner(self, *arguments, **kwargs):
        return subprocess.run([sys.executable, str(self.program), *arguments], cwd=self.root,
                              text=True, capture_output=True, timeout=10, **kwargs)

    def test_secret_staged_then_removed_from_worktree_still_blocks_delivery(self):
        source = self.root / "component.rs"
        source.write_text(self.token)
        self.git("add", "component.rs")
        source.write_text("clean worktree\n")
        result = self.run_scanner()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["result"], "FAIL")
        self.assertNotIn(self.token, result.stdout + result.stderr)

    def test_unstaged_secret_is_not_mistaken_for_the_clean_delivery_index(self):
        source = self.root / "component.rs"
        source.write_text("clean staged source\n")
        self.git("add", "component.rs")
        source.write_text(self.token)
        result = self.run_scanner()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["result"], "PASS")

    def test_deployment_credential_input_is_scanned_and_redacted(self):
        deployment = self.root / 'credentials.txt'
        secret = 'syntheticCloudflareInput01234567890123456789'
        deployment.write_text('[Cloudflare API Token]\nToken=' + secret + '\n')
        (self.root / 'component.rs').write_text(secret)
        self.git('add', 'component.rs')
        result = self.run_scanner('--private-input', str(deployment))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_credential_in_a_staged_filename_is_blocked_and_redacted(self):
        name = self.token + ".txt"
        (self.root / name).write_text("ordinary content\n")
        self.git("add", "--", name)
        result = self.run_scanner()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn(self.token, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["result"], "FAIL")

    @unittest.skipUnless(sys.platform == "linux", "Linux bounded-reader acceptance")
    def test_oversize_private_input_fails_before_allocating_the_whole_file(self):
        import resource

        private = self.root / "Prompt/Task-Now.txt"
        with private.open("wb") as stream:
            stream.seek(128 * 1024 * 1024)
            stream.write(b"x")

        def memory_limit():
            resource.setrlimit(resource.RLIMIT_AS, (96 * 1024 * 1024, 96 * 1024 * 1024))

        result = self.run_scanner(preexec_fn=memory_limit)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["result"], "ERROR")
        self.assertNotIn("MemoryError", result.stdout + result.stderr)

    def test_malformed_artifact_returns_a_typed_nonzero_result(self):
        artifact = self.root / "broken.apk"
        artifact.write_bytes(b"not an APK archive")
        result = self.run_scanner("--apk", str(artifact))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["result"], "ERROR")
        self.assertNotIn("Traceback", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
