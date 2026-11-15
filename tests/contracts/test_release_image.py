"""Protect the public OCI release image and isolated runtime contract."""
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ReleaseImageTests(unittest.TestCase):
    def test_apache_20_license_ships_with_python_and_oci_distributions(self):
        license_text = (ROOT / "LICENSE").read_text()
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("END OF TERMS AND CONDITIONS", license_text)
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(metadata["project"]["license"], "Apache-2.0")
        self.assertEqual(metadata["project"]["license-files"], ["LICENSE"])
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("COPY pyproject.toml README.md LICENSE ./", dockerfile)
        self.assertIn('LABEL org.opencontainers.image.licenses="Apache-2.0"',
                      dockerfile)
        self.assertIn("COPY LICENSE /usr/local/share/licenses/ssh-mcp/LICENSE",
                      dockerfile)
        self.assertIn("COPY THIRD_PARTY_NOTICES.md /usr/local/share/licenses/ssh-mcp/THIRD_PARTY_NOTICES.md", dockerfile)
        self.assertIn("COPY --chown=10001:10001 Dockerfile VERSION LICENSE THIRD_PARTY_NOTICES.md /validation/",
                      dockerfile)
        validator = (ROOT / "tests/tools/validate.py").read_text()
        self.assertIn('"LICENSE", "THIRD_PARTY_NOTICES.md", "pyproject.toml"', validator)
        self.assertIn("wheel includes canonical Apache-2.0 license", validator)

    def test_release_dockerfile_keeps_hardened_lab_runtime(self):
        production = (ROOT / "Dockerfile").read_text().splitlines()
        self.assertFalse((ROOT / "deploy/runtime_bootstrap.py").exists())
        from app import runtime_files
        self.assertTrue(Path(runtime_files.__file__).is_file())
        self.assertIn('CMD ["python", "-m", "app"]', production)
        self.assertIn("image: ",
                      (ROOT / "examples/basic/compose.yaml").read_text())
        self.assertIn("USER 10001:10001", production)
        self.assertIn("HEALTHCHECK", "\n".join(production))
        self.assertNotIn("COPY .ssh", "\n".join(production))
        self.assertNotIn("ARG TOKEN", "\n".join(production))

    def test_release_image_tag_is_embedded_in_runtime(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn('ARG APP_VERSION=""', dockerfile)
        self.assertIn('ARG BUILD_NUMBER=""', dockerfile)
        # Execute the exact Dockerfile Python command, only redirecting its
        # destination into a temporary directory instead of a privileged path.
        build_commands = [line for line in dockerfile.splitlines()
                          if line.startswith("RUN python -c ") and 'APP_VERSION' in line]
        self.assertEqual(len(build_commands), 1)
        parts = shlex.split(build_commands[0].removeprefix("RUN "))
        self.assertEqual(parts[:2], ["python", "-c"])
        self.assertEqual(parts[3], "/usr/local/share/ssh-mcp/version")
        scenarios = (
            ("0.1", "23", "0.1.23"),  # Generic release producer contract.
            ("8.5", "162", "8.5.162"),
            ("", "", ""),           # Local CI with no build arguments.
            ("0.1", "", None),     # Partial or malformed build arguments fail closed.
            ("", "23", None),
            ("0.1.${BUILD_NUMBER}", "23", None),
            ("0.1", "not-a-number", None),
        )
        for prefix, number, expected in scenarios:
            with self.subTest(prefix=prefix, number=number), tempfile.TemporaryDirectory() as tmp:
                destination = Path(tmp) / "version"
                env = {**os.environ, "APP_VERSION": prefix, "BUILD_NUMBER": number}
                result = subprocess.run(
                    [sys.executable, "-c", parts[2], str(destination)],
                    env=env, capture_output=True, text=True, timeout=10, check=False,
                )
                if expected is None:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(destination.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(destination.read_text(), expected)

    def test_runtime_tests_mandatory_for_final_oci_image(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("FROM runtime AS runtime-tests", dockerfile)
        self.assertIn("FROM runtime AS final", dockerfile)
        self.assertIn(
            "COPY --from=runtime-tests /usr/local/bin/ssh-mcp-history-db",
            dockerfile,
        )
        self.assertIn("coverage run tests/tools/run_unit_tests.py", dockerfile)
        self.assertIn("scripts/check_coverage.py /validation/coverage.json --min 95", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertNotIn("COPY --from=runtime-tests /validation", dockerfile)

    def test_version_is_reviewed_builder_template(self):
        template = (ROOT / "VERSION").read_text().strip()
        token = chr(36) + "{BUILD_NUMBER}"
        self.assertTrue(re.fullmatch(r"0\.1\." + re.escape(token), template))
        self.assertEqual(template.count(token), 1)

    def test_single_ci_image_build(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(workflow.count("docker/build-push-action@"), 1)
        self.assertEqual(workflow.count("docker/setup-buildx-action@"), 1)
        self.assertIn("file: Dockerfile", workflow)
        self.assertIn("push: false", workflow)
        self.assertIn("build-args: |\n            APP_VERSION=0.1\n            BUILD_NUMBER=231", workflow)
        self.assertIn("cache-from: type=gha,scope=ssh-mcp-ci", workflow)
        self.assertIn("cache-to: "+chr(36)+"{{ github.event_name == 'push' && ", workflow)
        self.assertIn("'type=gha,scope=ssh-mcp-ci,mode=max' || '' }}", workflow)
        self.assertNotIn("coverage run -m unittest", workflow)
        self.assertIn("python tests/tools/validate.py", workflow)
        validator = (ROOT / "tests/tools/validate.py").read_text()
        self.assertIn('"mypy", "--strict"', validator)
        self.assertIn('"check", "app", "ops", "tests", "scripts"', validator)
        self.assertIn("node --check", workflow)
        self.assertIn("node --version", workflow)
        self.assertIn("command -v node", workflow)

    def test_dependency_layers_do_not_depend_on_app_source(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        dependencies = dockerfile.split("FROM python:3.12-slim-bookworm AS application-wheel")[0]
        app_wheel = dockerfile.split("FROM python:3.12-slim-bookworm AS application-wheel")[1]
        base = dockerfile.split("FROM python:3.12-slim-bookworm AS runtime-base")[1]
        self.assertIn("AS dependency-wheels", dependencies)
        self.assertIn("COPY pyproject.toml", dependencies)
        self.assertNotIn("COPY app/", dependencies)
        self.assertIn("COPY app/", app_wheel)
        self.assertIn("pip wheel", app_wheel)
        self.assertIn("--no-deps", app_wheel)
        self.assertIn("COPY --from=dependency-wheels", base)
        self.assertIn("FROM runtime-base AS runtime", dockerfile)
        self.assertIn("FROM runtime AS runtime-tests", dockerfile)


    def test_public_ci_uses_github_hosted_runners_without_private_credentials(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(workflow.count("runs-on: ubuntu-24.04"), 2)
        self.assertEqual(workflow.count("runs-on:"), 2)
        self.assertNotIn("self-hosted", workflow)
        self.assertNotIn("fromJSON(", workflow)
        self.assertIn("needs: [python]", workflow)
        self.assertIn("PYTHON_RESULT:", workflow)
        self.assertIn('test "$PYTHON_RESULT" = success', workflow)
        self.assertIn("contents: read", workflow)
        for action in ("actions/checkout", "actions/setup-python",
                       "astral-sh/setup-uv", "docker/setup-buildx-action",
                       "docker/build-push-action"):
            self.assertRegex(workflow, re.escape(action) + r"@[a-f0-9]{40}")
        self.assertNotIn("unittest discover -s tests -p", workflow)
        self.assertNotIn("coverage run", workflow)
        self.assertIn("python tests/tools/validate.py", workflow)
        self.assertIn("python -m unittest tests.unit.test_lab_runner -q", workflow)
        self.assertIn("python scripts/check_public_docs.py", workflow)
        self.assertIn("python scripts/check_public_source.py", workflow)
        self.assertIn("node --check", workflow)
        self.assertIn("uv build --sdist --wheel", workflow)
        validator = (ROOT / "tests/tools/validate.py").read_text()
        self.assertIn("installed_wheel(temp, env)", validator)
        self.assertIn('"--min", "95"', validator)
        self.assertIn("assert tests import only the installed wheel and CLI", validator)

    def test_dockerhub_publish_requires_reviewed_main_and_smoke_test(self):
        workflow = (ROOT / ".github/workflows/docker-publish.yml").read_text()
        dockerfile = (ROOT / "Dockerfile").read_text()
        validator = (ROOT / "tests/tools/validate.py").read_text()

        self.assertIn("on:\n  workflow_dispatch:", workflow)
        self.assertNotIn("  pull_request:", workflow)
        self.assertIn("github.repository == 'keeperlink/ssh-mcp'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn('test "$latest" = "$GITHUB_SHA:success"', workflow)
        self.assertIn("gh api", workflow)
        self.assertIn("cache-from: type=gha,scope=ssh-mcp-ci", workflow)
        self.assertEqual(workflow.count("docker/build-push-action@"), 1)
        self.assertEqual(workflow.count("docker/login-action@"), 1)
        self.assertIn("environment: dockerhub-publish", workflow)
        self.assertIn("outputs: type=oci,dest=", workflow)
        self.assertIn("skopeo inspect --raw", workflow)
        self.assertIn("docker-archive:", workflow)
        self.assertIn("docker load --input", workflow)
        self.assertNotIn("docker-daemon:", workflow)
        self.assertIn("skopeo copy --all --preserve-digests", workflow)
        self.assertIn('for tag in "$VERSION" latest; do', workflow)
        self.assertIn('test "$actual" = "$expected"', workflow)
        self.assertIn('sha256sum', workflow)
        self.assertIn("Build attested OCI archive", workflow)
        self.assertIn("Publish tested OCI index", workflow)
        self.assertNotIn("docker push", workflow)
        self.assertNotIn("push: true", workflow)
        for action in ("actions/checkout", "docker/setup-buildx-action",
                       "docker/build-push-action", "docker/login-action"):
            self.assertRegex(workflow, re.escape(action) + r"@[a-f0-9]{40}")
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("load: true", workflow)
        self.assertIn("sbom: true", workflow)
        self.assertIn("provenance: mode=max", workflow)
        self.assertIn("APP_VERSION=0.1", workflow)
        self.assertIn("BUILD_NUMBER=", workflow)
        self.assertIn("0.1."+chr(36)+"{{ github.run_number }}", workflow)
        self.assertIn("keeperlink/ssh-mcp", workflow)
        self.assertIn("DOCKERHUB_USERNAME", workflow)
        self.assertIn("DOCKERHUB_TOKEN", workflow)
        guide = (ROOT / "docs/container-publishing.md").read_text()
        for phrase in ("environment secrets", "Selected branches and tags",
                       "only", "main", "repository-level secrets", "unprotected environment"):
            self.assertIn(phrase, guide)
        self.assertLess(workflow.index("name: Verify OCI index and load runnable image"),
                        workflow.index("name: Smoke test"))
        self.assertLess(workflow.index("name: Smoke test"),
                        workflow.index("name: Login to Docker Hub"))
        self.assertLess(workflow.index("name: Login to Docker Hub"),
                        workflow.index("name: Publish tested OCI index"))
        self.assertLess(workflow.index("name: Check release tag"),
                        workflow.index("name: Login to Docker Hub"))
        for item in ("--network none", "--read-only", "--cap-drop ALL",
                     "MCP_SSH_TOOLS_ENABLED=false", "MCP_CIMD_VALIDATE_REMOTE=false",
                     "Unauthenticated MCP call was accepted", "test -z"):
            self.assertIn(item, workflow)
        self.assertNotIn("--privileged", workflow)
        self.assertIn("COPY --chown=10001:10001 .github/workflows/docker-publish.yml "
                      "/validation/.github/workflows/docker-publish.yml", dockerfile)
        self.assertIn('".github/workflows/docker-publish.yml"', validator)
        self.assertIn("COPY --chown=10001:10001 docs/container-publishing.md "
                      "/validation/docs/container-publishing.md", dockerfile)
        self.assertIn('"docs/container-publishing.md"', validator)

    def test_hardened_public_compose_has_no_extra_privileges(self):
        compose = (ROOT / "examples/hardened/compose.yaml").read_text()
        for expected in ("read_only: true", "no-new-privileges:true", "cap_drop:"):
            self.assertIn(expected, compose)
        self.assertNotIn("docker.sock", compose)


if __name__ == "__main__":
    unittest.main()
