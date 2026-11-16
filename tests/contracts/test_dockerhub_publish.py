"""Public hosted CI and Docker Hub release-publisher safety contracts."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class DockerHubPublishingContracts(unittest.TestCase):
    def test_release_uses_updated_debian_base_and_applies_security_updates(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        for stage in ("dependency-wheels", "application-wheel", "runtime-base"):
            self.assertIn(f"FROM python:3.12-slim-trixie AS {stage}", dockerfile)
        self.assertEqual(dockerfile.count("FROM python:3.12-slim-trixie AS"), 3)
        self.assertNotIn("python:3.12-slim-bookworm", dockerfile)
        self.assertIn("RUN apt-get update && apt-get upgrade -y", dockerfile)
        self.assertIn("apt-get install -y --no-install-recommends openssh-client ca-certificates",
                      dockerfile)
        self.assertIn("rm -rf /var/lib/apt/lists/*", dockerfile)

    def test_single_ci_image_build(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(workflow.count("docker/build-push-action@"), 1)
        self.assertEqual(workflow.count("docker/setup-buildx-action@"), 1)
        self.assertIn("file: Dockerfile", workflow)
        self.assertIn("push: false", workflow)
        self.assertIn("pull: true", workflow)
        self.assertEqual(workflow.count("no-cache-filters: runtime-base"), 1)
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


    def test_getting_started_runs_published_image_without_source_build(self):
        guide = (ROOT / "docs/getting-started.md").read_text()
        compose = (ROOT / "examples/basic/compose.yaml").read_text()
        self.assertIn("image: ssh-mcp:basic", compose)
        published = guide.index("docker pull keeperlink/ssh-mcp:0.1.1")
        tag = guide.index("docker image tag keeperlink/ssh-mcp:0.1.1 ssh-mcp:basic")
        start = guide.index("up -d --no-build --pull never", tag)
        source = guide.index("**Alternatively**, to build the image", start)
        self.assertLess(published, tag)
        self.assertLess(tag, start)
        self.assertLess(start, source)
        self.assertNotIn("compose.yaml build", guide[published:source])
        self.assertIn("compose.yaml build", guide[source:])
        self.assertIn("Docker Engine 28.0.0 or newer", guide)
        self.assertIn("existing HTTPS", guide)
        # The public-only fixture manifest and common Dockerfile make this
        # safety contract mandatory in the installed wheel and OCI test stage.
        self.assertIn("COPY --chown=10001:10001 docs/ /validation/docs/",
                      (ROOT / "Dockerfile").read_text())
        self.assertIn("docs/getting-started.md",
                      (ROOT / "tests/tools/fixture-extra.txt").read_text())


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
        self.assertIn("pull: true", workflow)
        self.assertEqual(workflow.count("no-cache-filters: runtime-base"), 1)
        self.assertEqual(workflow.count("docker/build-push-action@"), 1)
        self.assertEqual(workflow.count("docker/login-action@"), 1)
        self.assertIn("environment: dockerhub-publish", workflow)
        self.assertIn("outputs: type=oci,dest=", workflow)
        self.assertIn("skopeo inspect --raw", workflow)
        self.assertIn("docker-archive:", workflow)
        self.assertIn("docker load --input", workflow)
        self.assertNotIn("docker-daemon:", workflow)
        # Copy the OCI source only once; retag from the published index
        # rather than copying an OCI index over an existing latest tag.
        self.assertEqual(workflow.count("skopeo copy --all --preserve-digests"), 1)
        self.assertIn('"$source" "docker://docker.io/${IMAGE}:${VERSION}"', workflow)
        self.assertIn("docker buildx imagetools create", workflow)
        self.assertIn('--tag "docker.io/${IMAGE}:latest"', workflow)
        self.assertIn('"docker.io/${IMAGE}:${VERSION}"', workflow)
        self.assertIn('for tag in "$VERSION" latest; do', workflow)
        self.assertIn("docker buildx imagetools inspect --raw", workflow)
        self.assertIn('test "$actual" = "$expected"', workflow)
        self.assertLess(workflow.index("skopeo copy --all --preserve-digests"),
                        workflow.index("docker buildx imagetools create"))
        self.assertLess(workflow.index("docker buildx imagetools create"),
                        workflow.index('for tag in "$VERSION" latest; do'))
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
        # Keep public publisher checks mandatory in both installed-wheel and
        # OCI runtime tests while the private repository has no publisher flow.
        self.assertIn("COPY --chown=10001:10001 .github/workflows/ "
                      "/validation/.github/workflows/", dockerfile)
        extras = (ROOT / "tests/tools/fixture-extra.txt").read_text()
        self.assertIn(".github/workflows/docker-publish.yml", extras)
        self.assertIn("docs/container-publishing.md", extras)
        self.assertIn("fixture-extra.txt", validator)
        self.assertIn("python tests/tools/validate.py",
                      (ROOT / ".github/workflows/ci.yml").read_text())
