"""Keep platform, FFI and HTTP dependencies out of the Rust domain crate."""
import importlib.util
from pathlib import Path
import tomllib
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/verify_architecture.py"
spec = importlib.util.spec_from_file_location("verify_architecture", path)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_accepts_the_existing_domain_crypto_dependencies(self):
        manifest = tomllib.loads('[dependencies]\nbase64 = "=0.22.1"\nzeroize = { workspace = true }\n')
        workspace = tomllib.loads('[workspace.dependencies]\nzeroize = "=1.9.2"\n')
        self.assertEqual(guard.violations(manifest, workspace), [])

    def test_rejects_a_platform_dependency_in_production(self):
        manifest = tomllib.loads('[dependencies]\njni = "=0.21.1"\n')
        self.assertTrue(guard.violations(manifest, {}))

    def test_rejects_a_renamed_workspace_platform_dependency(self):
        manifest = tomllib.loads('[dependencies]\nbridge = { workspace = true }\n')
        workspace = tomllib.loads('[workspace.dependencies]\nbridge = { package = "uniffi", version = "=0.32.2" }\n')
        self.assertTrue(guard.violations(manifest, workspace))

    def test_allows_domain_serialization_but_rejects_sqlcipher(self):
        manifest = tomllib.loads('[dependencies]\nserde = { workspace = true }\n')
        workspace = tomllib.loads('[workspace.dependencies]\nserde = { version = "=1.0.228", features = ["derive"] }\n')
        self.assertEqual(guard.violations(manifest, workspace), [])
        manifest["dependencies"]["database"] = {"package": "rusqlite", "version": "=0.43.0"}
        self.assertEqual(guard.violations(manifest, workspace), ["dependencies:database:unapproved_domain_dependency"])

    def test_rejects_target_specific_platform_dependencies(self):
        manifest = tomllib.loads('[target.\'cfg(target_os = "android")\'.dependencies]\nndk = "=0.9.0"\n')
        self.assertTrue(guard.violations(manifest, {}))

    def test_cannot_hide_a_platform_path_under_an_approved_dependency_name(self):
        manifest = tomllib.loads('[dependencies]\nbase64 = { path = "../platform" }\n')
        self.assertTrue(guard.violations(manifest, {}))

    def test_fixture_only_dependencies_do_not_change_the_runtime_boundary(self):
        manifest = tomllib.loads('[dev-dependencies]\nrcgen = "=0.14.10"\nserde_json = "=1.0.145"\n')
        self.assertEqual(guard.violations(manifest, {}), [])


if __name__ == "__main__":
    unittest.main()
