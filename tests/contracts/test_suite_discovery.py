"""Offline test discovery must never import real integration entrypoints."""
from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from tests.tools.run_unit_tests import discover
from tests.tools import validate


class SuiteDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "tests"
        (self.root / "unit").mkdir(parents=True)
        (self.root / "contracts").mkdir()

    def sample(self, suite: str, name: str) -> None:
        directory = self.root / suite
        directory.mkdir(exist_ok=True)
        (directory / name).write_text(
            "import unittest\n"
            "class SampleTests(unittest.TestCase):\n"
            "    def test_sample(self):\n"
            "        self.assertTrue(True)\n"
        )

    def test_offline_suite_finds_unit_and_contracts(self) -> None:
        self.sample("unit", f"test_unit_{uuid4().hex}.py")
        self.sample("contracts", f"test_contract_{uuid4().hex}.py")
        self.assertEqual(discover(tests=self.root).countTestCases(), 2)

    def test_tools_are_discovered_only_when_selected(self) -> None:
        self.sample("unit", f"test_unit_{uuid4().hex}.py")
        self.sample("contracts", f"test_contract_{uuid4().hex}.py")
        self.sample("tools", f"test_tools_{uuid4().hex}.py")
        self.assertEqual(discover(tests=self.root).countTestCases(), 2)
        self.assertEqual(discover(tests=self.root, tools_only=True).countTestCases(), 1)

    def test_unselected_source_only_modules_are_not_imported(self) -> None:
        self.sample("unit", f"test_unit_{uuid4().hex}.py")
        self.sample("contracts", f"test_contract_{uuid4().hex}.py")
        tools = self.root / "tools"
        tools.mkdir()
        (tools / f"test_tools_{uuid4().hex}.py").write_text(
            "raise RuntimeError('Source-only dependency is not installed')\n")
        self.assertEqual(discover(tests=self.root).countTestCases(), 2)
        with self.assertRaisesRegex(ValueError, "Failed tests/tools discovery"):
            discover(tests=self.root, tools_only=True)

    def test_duplicate_module_names_between_tools_and_wheel_tests_are_rejected(self) -> None:
        name = f"test_duplicate_{uuid4().hex}.py"
        self.sample("unit", name)
        self.sample("contracts", f"test_contract_{uuid4().hex}.py")
        self.sample("tools", name)
        for tools_only in (False, True):
            with self.assertRaisesRegex(ValueError, "Duplicate test module"):
                discover(tests=self.root, tools_only=tools_only)

    def test_missing_tools_suite_fails_only_when_selected(self) -> None:
        self.sample("unit", f"test_unit_{uuid4().hex}.py")
        self.sample("contracts", f"test_contract_{uuid4().hex}.py")
        self.assertEqual(discover(tests=self.root).countTestCases(), 2)
        with self.assertRaisesRegex(ValueError, "Missing or empty offline suite: tests/tools"):
            discover(tests=self.root, tools_only=True)

    def test_root_tests_are_rejected_not_silently_omitted(self) -> None:
        self.sample("unit", f"test_unit_{uuid4().hex}.py")
        self.sample("contracts", f"test_contract_{uuid4().hex}.py")
        (self.root / "test_orphan.py").write_text("# orphan\n")
        with self.assertRaisesRegex(ValueError, "tests/unit, tests/contracts or tests/tools"):
            discover(tests=self.root)

    def test_duplicate_module_names_across_suites_are_rejected(self) -> None:
        name = f"test_duplicate_{uuid4().hex}.py"
        self.sample("unit", name)
        self.sample("contracts", name)
        with self.assertRaisesRegex(ValueError, "Duplicate test module"):
            discover(tests=self.root)

    def test_misplaced_tests_in_any_directory_fail_discovery(self) -> None:
        self.sample("unit", f"test_unit_{uuid4().hex}.py")
        self.sample("contracts", f"test_contract_{uuid4().hex}.py")
        for name in (
            "test_orphan.py",
            "integration/test_accidental.py",
            "fixtures/test_accidental.py",
            "lab/test_accidental.py",
            "tools/nested/test_accidental.py",
            "unit/nested/test_accidental.py",
            "contracts/nested/test_accidental.py",
            "other/test_accidental.py",
        ):
            with self.subTest(name=name):
                misplaced = self.root / name
                misplaced.parent.mkdir(parents=True, exist_ok=True)
                misplaced.write_text("# a lost test must stop the build\n")
                with self.assertRaisesRegex(ValueError, "tests/unit, tests/contracts or tests/tools"):
                    discover(tests=self.root)
                misplaced.unlink()

    @staticmethod
    def contaminated_environment(directory: Path) -> dict[str, str]:
        # All paths and credentials below are synthetic, never host service state.
        entries = {
            "MCP_CONFIG_FILE": directory / "service.json",
            "MCP_INVENTORY_FILE": directory / "inventory.json",
            "MCP_KNOWN_HOSTS_FILE": directory / "known_hosts",
            "MCP_SECRETS_FILE": directory / "secrets.json",
            "MCP_OAUTH_DB": directory / "oauth.sqlite",
            "SSH_JOBS_DB": directory / "jobs.sqlite",
            "SSH_INVENTORY_FILE": directory / "ssh-inventory.json",
        }
        for path in entries.values():
            path.write_text("synthetic-poisoned-file")
        return {
            **{key: str(path) for key, path in entries.items()},
            "MCP_ENVIRONMENT": "production",
            "MCP_ISSUER": "https://real-issuer.invalid",
            "MCP_LOGIN_KEY": "synthetic-inherited-key-not-for-unit-tests",
            "MCP_TOKEN_SIGNING_SECRET": "synthetic-inherited-signing-not-for-unit-tests",
            "SSH_EXECUTOR_ENABLED": "true",
            "HISTORY_VIEWER_ENABLED": "true",
            "HISTORY_VIEWER_PASSWORD": "synthetic-inherited-viewer",
            "REQUEST_TIMEOUT": "999",
            "WEB_CONCURRENCY": "12",
            "UVICORN_WORKERS": "4",
        }

    def test_direct_discovery_ignores_managed_mounts_and_databases(self) -> None:
        self.sample("unit", f"test_unit_{uuid4().hex}.py")
        self.sample("contracts", f"test_contract_{uuid4().hex}.py")
        contaminated = self.contaminated_environment(self.root)
        # A fresh interpreter imports app.config only after test discovery;
        # leaked mount selectors would force parsing invalid real-file inputs.
        source = (
            "from pathlib import Path\n"
            "import os,sys\n"
            "from tests.tools.run_unit_tests import discover\n"
            "assert discover(tests=Path(sys.argv[1])).countTestCases()==2\n"
            "from app import config\n"
            "assert config.MCP_ENVIRONMENT=='lab'\n"
            "assert config.MCP_ISSUER=='http://localhost'\n"
            "assert config.MCP_LOGIN_KEY.startswith('synthetic-test-login-')\n"
            "for name in ('MCP_CONFIG_FILE','MCP_INVENTORY_FILE','MCP_KNOWN_HOSTS_FILE',"
            "'MCP_SECRETS_FILE','MCP_OAUTH_DB','SSH_JOBS_DB','SSH_INVENTORY_FILE',"
            "'HISTORY_VIEWER_ENABLED','HISTORY_VIEWER_PASSWORD','WEB_CONCURRENCY',"
            "'UVICORN_WORKERS'):\n"
            "    assert name not in os.environ, name\n"
        )
        child = subprocess.run(
            [sys.executable, "-c", source, str(self.root)],
            env={**os.environ, **contaminated},
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(child.returncode, 0, child.stderr[-1500:])

    def test_validator_scrubs_service_environment_for_all_children(self) -> None:
        contaminated = self.contaminated_environment(self.root)
        sent = []
        with patch.dict(os.environ, contaminated):
            with patch.object(validate, "run", side_effect=lambda *_a, **kw: sent.append(kw["env"])):
                self.assertEqual(validate.main(["--mode", "lint"]), 0)
            self.assertIn("MCP_CONFIG_FILE", os.environ)
        self.assertEqual(len(sent), 4)
        for env in sent:
            self.assertEqual(env["MCP_ISSUER"], "http://localhost")
            self.assertEqual(env["MCP_RESOURCE"], "http://localhost/mcp")
            self.assertEqual(env["MCP_CIMD_VALIDATE_REMOTE"], "false")
            for name in contaminated:
                if name in ("MCP_ISSUER", "MCP_LOGIN_KEY", "MCP_TOKEN_SIGNING_SECRET"):
                    self.assertNotEqual(env[name], contaminated[name], name)
                    continue
                if name.startswith(("MCP_", "SSH_", "HISTORY_")) or name in (
                    "REQUEST_TIMEOUT", "WEB_CONCURRENCY", "UVICORN_WORKERS",
                ):
                    self.assertNotIn(name, env, name)

    def test_entrypoints_import_helper_from_selected_checkout(self) -> None:
        # Simulate PYTHONPATH containing an older checkout before this one.
        # Both entrypoints must use the helper next to their current source.
        checkout = Path(__file__).resolve().parents[2]
        shadow = self.root.parent / "older-checkout"
        helper = shadow / "tests" / "tools"
        helper.mkdir(parents=True)
        (shadow / "tests" / "__init__.py").write_text("")
        (helper / "__init__.py").write_text("")
        (helper / "_offline_env.py").write_text(
            "raise RuntimeError('Loaded helper from older checkout')\n"
        )
        probe = (
            "from pathlib import Path\n"
            "import runpy,sys\n"
            "shadow,checkout,script = (Path(x).resolve() for x in sys.argv[1:])\n"
            "sys.path[:] = [str(shadow), str(checkout)] + "
            "[x for x in sys.path if x not in (str(shadow),str(checkout))]\n"
            "assert sys.path.index(str(shadow)) < sys.path.index(str(checkout))\n"
            "runpy.run_path(str(script), run_name='offline_bootstrap_probe')\n"
            "helper = sys.modules['tests.tools._offline_env']\n"
            "assert Path(helper.__file__).resolve() == "
            "checkout / 'tests/tools/_offline_env.py'\n"
            "assert sys.path[0] == str(checkout)\n"
        )
        for entrypoint in ("run_unit_tests.py", "validate.py"):
            with self.subTest(entrypoint=entrypoint):
                result = subprocess.run(
                    [sys.executable, "-c", probe, str(shadow), str(checkout),
                     str(checkout / "tests" / "tools" / entrypoint)],
                    cwd=checkout,
                    env={**os.environ, "PYTHONPATH": str(shadow) + os.pathsep + str(checkout)},
                    capture_output=True, text=True, timeout=20, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])

    def test_missing_suite_fails_closed(self) -> None:
        self.sample("unit", f"test_unit_{uuid4().hex}.py")
        with self.assertRaisesRegex(ValueError, "Missing or empty offline suite"):
            discover(tests=self.root)


if __name__ == "__main__":
    unittest.main()
