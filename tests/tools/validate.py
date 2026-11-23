#!/usr/bin/env python3
"""Complete offline Python validation for ssh-mcp.

Run with `python tests/tools/validate.py` for all gates, or use --mode
lint/unit. Installs a local wheel into a temporary target and tests it
outside the source checkout, reproducing the mandatory OCI test layout.
Requires a Python 3.14 environment prepared from requirements-dev.txt.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
MYPY_FILES = (
    "app/contracts.py", "app/ssh_executor.py", "app/jobs.py",
    "app/history.py", "app/observability.py", "app/form_body.py", "app/runtime_files.py",
    "app/control.py", "app/control_cli.py", "app/request_trace.py", "ops/preview/preview.py",
    "app/file_audit.py", "app/file_helper.py", "app/file_transport.py",
    "app/file_ops.py", "app/host_relay.py", "app/relay_scripts.py",
    "ops/history_db.py", "ssh_mcp_secrets/cli.py",
    "ssh_mcp_secrets/batch.py", "ssh_mcp_secrets/apply.py",
    "scripts/check_coverage.py",
    "scripts/sync_requirements_dev.py", "tests/tools/validate.py",
    "tests/tools/run_unit_tests.py", "tests/tools/_offline_env.py",
)
# The installed-wheel validator must sanitize every subprocess before any
# app import; the unit runner repeats this protection when run standalone.
# A previous checkout may already be on sys.path ahead of this one.
# Resolve the tests helper from the selected checkout, not an older sibling.
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))
from tests.tools._offline_env import offline_environment  # noqa: E402



def run(label: str, args: list[str], *, cwd: Path = ROOT,
        env: dict[str, str] | None = None) -> None:
    print(f"CHECK: {label}", flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=420)
    print(f"PASS: {label}", flush=True)


def fixture(root: Path) -> Path:
    """Mirror the contents of Dockerfile's /validation, never copy app/."""
    directory = root / "validation"
    directory.mkdir()
    shutil.copytree(ROOT / "tests", directory / "tests", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    common = (
        "scripts/check_coverage.py", "ops/history_db.py",
        "deploy/service.example.json", "examples/basic/compose.yaml", "examples/hardened/compose.yaml",
        "Dockerfile", "VERSION", "LICENSE", "THIRD_PARTY_NOTICES.md", "pyproject.toml",
        ".github/workflows/ci.yml",
    )
    # Each producer declares only its additional test-fixture inputs. Missing,
    # duplicate, redirected or traversal paths fail closed.
    manifest = ROOT / "tests/tools/fixture-extra.txt"
    extras: list[str] = []
    if manifest.exists():
        for source in manifest.read_text(encoding="utf-8").splitlines():
            source = source.strip()
            if not source or source.startswith("#"):
                continue
            relative = Path(source)
            if (relative.is_absolute() or ".." in relative.parts
                    or not (source.startswith("docs/") or source.startswith(".github/workflows/"))
                    or source in common or source in extras):
                raise RuntimeError(f"Invalid installed-wheel fixture asset: {source}")
            file = ROOT / relative
            if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(ROOT):
                raise RuntimeError(f"Missing or unsafe installed-wheel fixture asset: {source}")
            extras.append(source)
    for source in (*common, *extras):
        target = directory / source
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / source, target)
    return directory


def coverage_checks(directory: Path, env: dict[str, str], title: str,
                    python: Path) -> None:
    location = directory / "coverage.json"
    run(f"{title} full Python test suite",
        [str(python), "-m", "coverage", "run",
         "tests/tools/run_unit_tests.py"],
        cwd=directory, env={**env, "COVERAGE_FILE": str(directory / ".coverage")})
    run(f"{title} coverage report",
        [str(python), "-m", "coverage", "json", "-o", str(location)],
        cwd=directory, env={**env, "COVERAGE_FILE": str(directory / ".coverage")})
    run(f"{title} combined coverage >=95%",
        [str(python), "scripts/check_coverage.py", str(location), "--min", "95"],
        cwd=directory, env=env)


def installed_wheel(temp: Path, env: dict[str, str]) -> None:
    wheels = temp / "wheels"
    wheels.mkdir()
    run("build distribution wheel without network access",
        [sys.executable, "-m", "pip", "wheel", "--no-index", "--no-cache-dir", "--no-deps",
         "--no-build-isolation", "--wheel-dir", str(wheels), "."], env=env)
    packages = list(wheels.glob("ssh_mcp-*.whl"))
    if len(packages) != 1:
        raise RuntimeError("Expected exactly one ssh-mcp built wheel")

    with ZipFile(packages[0]) as wheel:
        license_files = [name for name in wheel.namelist()
                         if name.endswith(".dist-info/licenses/LICENSE")]
        metadata_files = [name for name in wheel.namelist()
                          if name.endswith(".dist-info/METADATA")]
        if len(license_files) != 1 or len(metadata_files) != 1:
            raise RuntimeError("Wheel must include exactly one license and metadata file")
        if wheel.read(license_files[0]) != (ROOT / "LICENSE").read_bytes():
            raise RuntimeError("Wheel license does not match source Apache-2.0 license")
        if "License-Expression: Apache-2.0" not in wheel.read(metadata_files[0]).decode():
            raise RuntimeError("Wheel must declare Apache-2.0 metadata")
    print("PASS: wheel includes canonical Apache-2.0 license and metadata", flush=True)

    # Build an independent interpreter and CLI so oauth-sessions really exists.
    # Reuse the already-provisioned, pinned dependency site-packages read-only:
    # never pip-install or alter the development-helper managed environment.
    virtualenv = temp / "venv"
    run(f"create temporary isolated Python {sys.version_info.major}.{sys.version_info.minor} virtualenv",
        [sys.executable, "-m", "venv", str(virtualenv)], env=env)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site = virtualenv / "lib" / version / "site-packages"
    dependency_site = Path(sys.prefix) / "lib" / version / "site-packages"
    if not dependency_site.is_dir() or not site.is_dir():
        raise RuntimeError("Cannot locate installed pinned Python dependencies")
    (site / "pinned-dependencies.pth").write_text(
        str(dependency_site.resolve()) + chr(10), encoding="utf-8"
    )
    isolated_python = virtualenv / "bin" / "python"
    run("install wheel with real console scripts",
        [str(isolated_python), "-m", "pip", "install", "--no-index", "--no-deps",
         str(packages[0])], env=env)
    validation = fixture(temp)
    isolated_env = dict(env, PYTHONNOUSERSITE="1")
    isolated_env.pop("PYTHONPATH", None)
    run("assert tests import only the installed wheel and CLI",
        [str(isolated_python), "-c",
         "import app,ssh_mcp_secrets,sys;from pathlib import Path;"
         "venv=Path(sys.prefix).resolve();"
         "path=Path(app.__file__).resolve();"
         "assert path.is_relative_to(venv),(path,venv);"
         "path=Path(ssh_mcp_secrets.__file__).resolve();"
         "assert path.is_relative_to(venv),(path,venv);"
         "assert (venv/'bin'/'oauth-sessions').is_file();"
         "assert (venv/'bin'/'ssh-mcp-ctl').is_file();"
         "assert (venv/'bin'/'ssh-mcp-secrets').is_file();"
         "assert (venv/'bin'/'ssh-mcp-secrets-apply').is_file()"],
        cwd=validation, env=isolated_env)
    coverage_checks(validation, isolated_env, "installed-wheel", isolated_python)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("all", "lint", "unit"), default="all")
    args = parser.parse_args(argv)
    if sys.version_info[:2] != (3, 14):
        print("FAIL: full validator requires Python 3.14", file=sys.stderr)
        return 1
    env = offline_environment(os.environ)
    checks = 0
    try:
        run("development pins match pyproject",
            [sys.executable, "scripts/sync_requirements_dev.py"], env=env)
        checks += 1
        if args.mode != "unit":
            run("compile Python source",
                [sys.executable, "-m", "compileall", "-q", "app", "ssh_mcp_secrets", "ops",
                 "scripts", "tests"], env=env)
            run("Ruff", [str(Path(sys.executable).parent / "ruff"),
                         "check", "app", "ssh_mcp_secrets", "ops", "tests", "scripts"], env=env)
            run("mypy strict", [sys.executable, "-m", "mypy", "--strict", *MYPY_FILES],
                env=env)
            checks += 3
        if args.mode != "lint":
            # Source-only tooling tests require the checkout and development
            # dependencies unavailable in the minimal runtime-test image.
            run("development dependency-lock and source-tool regression tests",
                [sys.executable, "tests/tools/run_unit_tests.py", "--tools"], env=env)
            with tempfile.TemporaryDirectory(prefix="sky235-validation-") as folder:
                temp = Path(folder)
                installed_wheel(temp, env)
            checks += 8
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        print(f"FAIL: complete validation: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return 1
    print(f"Validation passed: {checks}/{checks} gates.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
