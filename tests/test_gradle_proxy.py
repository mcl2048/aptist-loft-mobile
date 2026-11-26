"""Catch ignored proxy settings and credentials exposed in Java arguments."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/run_gradle.py"
spec = importlib.util.spec_from_file_location("run_gradle", path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class GradleProxyTests(unittest.TestCase):
    def test_https_proxy_is_applied_to_both_java_transports(self):
        self.assertEqual(runner.proxy_properties({"HTTPS_PROXY": "http://proxy.example.test:10911"}), [
            "-Dhttp.proxyHost=proxy.example.test", "-Dhttp.proxyPort=10911",
            "-Dhttps.proxyHost=proxy.example.test", "-Dhttps.proxyPort=10911",
            "-Dhttp.nonProxyHosts=localhost|127.*|[::1]",
        ])

    def test_no_proxy_does_not_change_java_networking(self):
        self.assertEqual(runner.proxy_properties({}), [])

    def test_credential_proxy_is_rejected_without_echoing_secret(self):
        with self.assertRaises(ValueError) as caught:
            runner.proxy_properties({"HTTPS_PROXY": "http://user:synthetic-password@proxy.example.test:8080"})
        self.assertNotIn("synthetic-password", str(caught.exception))

    def test_invalid_proxy_port_is_rejected(self):
        with self.assertRaises(ValueError):
            runner.proxy_properties({"HTTPS_PROXY": "http://proxy.example.test:70000"})

    def test_java_option_injection_in_proxy_host_is_rejected(self):
        with self.assertRaises(ValueError):
            runner.proxy_properties({"HTTPS_PROXY": "http://proxy.example.test -Dunsafe=true:8080"})


if __name__ == "__main__":
    unittest.main()
