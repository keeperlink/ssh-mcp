"""The full-validator lock must support development-helper's --no-deps environment."""
from __future__ import annotations

from importlib import metadata
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import sync_requirements_dev as lock


class DevelopmentDependencyLockTests(unittest.TestCase):
    def test_full_lock_includes_required_transitive_packages(self):
        pins = lock.resolved_closure()
        self.assertTrue(lock.requirements().keys() <= pins.keys())
        # Regression for the initial TEST-235 post-merge failure: mypy imports
        # librt, and development-helper installs packages without dependency resolving.
        self.assertIn("librt", pins)
        self.assertIn("mypy-extensions", pins)
        self.assertIn("pydantic-core", pins)
        self.assertIn("mcp-types", pins)
        # mcp depends on pyjwt[crypto], so marker-aware extras matter.
        self.assertIn("cryptography", pins)
        self.assertIn("cffi", pins)
        self.assertGreater(len(pins), len(lock.requirements()))
        self.assertTrue(all(pins[name] == metadata.version(name)
                            for name in pins))

    def test_full_generated_pins_match_installed_closure(self):
        lock.check()

    def test_direct_only_pins_are_rejected(self):
        roots = {
            name: metadata.version(name)
            for name in lock.requirements()
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "requirements-dev.txt"
            path.write_text(lock.render(roots))
            with patch.object(lock, "OUTPUT", path):
                with self.assertRaisesRegex(ValueError, "closure mismatch.*missing="):
                    lock.check()

    def test_missing_transitive_wheel_is_rejected(self):
        pins = lock.resolved_closure()
        self.assertIn("librt", pins)
        del pins["librt"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "requirements-dev.txt"
            path.write_text(lock.render(pins))
            with patch.object(lock, "OUTPUT", path):
                with self.assertRaisesRegex(ValueError, "missing=\\['librt'\\]"):
                    lock.check()

    def test_wrong_pin_and_extraneous_wheel_are_rejected(self):
        pins = lock.resolved_closure()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "requirements-dev.txt"
            with patch.object(lock, "OUTPUT", path):
                version = pins["librt"]
                pins["librt"] = "0.0.0"
                path.write_text(lock.render(pins))
                with self.assertRaisesRegex(ValueError, "differs from pinned"):
                    lock.check()
                pins["librt"] = version
                pins["not-required-wheel"] = "1.0.0"
                path.write_text(lock.render(pins))
                with self.assertRaisesRegex(ValueError, "extra="):
                    lock.check()


if __name__ == "__main__":
    unittest.main()
