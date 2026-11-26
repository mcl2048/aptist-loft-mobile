"""Catch task credential disclosure and unsafe delivery-address acceptance."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "task_context.py"
SPEC = importlib.util.spec_from_file_location("task_context", MODULE)
task_context = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(task_context)
SECRET = "github_pat_" + "syntheticCredentialOnly0123456789" * 2
TASK = (
    '[Task No.] " loftmobile-1125-01 "\n'
    '[ 交付仓库 ] https://github.com/mcl2048/aptist-loft-mobile.git\n'
    f'[ Github Token ] {SECRET}\n'
    '[ 项目设计原始文档 ] /home/coder/LOFT-mobile/guide/guide.md\n'
)


class TaskContextTests(unittest.TestCase):
    def test_redaction_removes_credential_field_and_repeated_value(self):
        result = task_context.redact_text(TASK + f"accidental mention: {SECRET}\n")
        self.assertNotIn(SECRET, result)
        self.assertIn("[REDACTED]", result)
        self.assertIn("loftmobile-1125-01", result)

    def test_public_context_preserves_task_and_repository_without_secret(self):
        result = task_context.public_context(TASK)
        self.assertEqual(result["task_no"], "loftmobile-1125-01")
        self.assertEqual(result["repository"], "https://github.com/mcl2048/aptist-loft-mobile.git")
        self.assertTrue(result["credential_present"])
        self.assertNotIn(SECRET, repr(result))

    def test_credential_remains_available_only_to_internal_authentication(self):
        self.assertEqual(task_context.credential(TASK), SECRET)

    def test_rejects_repository_urls_with_embedded_credentials(self):
        unsafe = TASK.replace("https://github.com/", "https://user:password@github.com/")
        with self.assertRaises(ValueError):
            task_context.public_context(unsafe)

    def test_rejects_non_github_delivery_destination(self):
        unsafe = TASK.replace("github.com", "attacker.example.test")
        with self.assertRaises(ValueError):
            task_context.public_context(unsafe)

    def test_missing_credential_error_contains_no_private_task(self):
        with self.assertRaises(ValueError) as caught:
            task_context.credential('[Task No.] " private label "\n')
        self.assertNotIn("private label", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
