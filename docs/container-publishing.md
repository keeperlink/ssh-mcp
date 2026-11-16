# Publishing to Docker Hub

SSH-MCP uses the same manual, test-before-publish approach as
[request-info-docker](https://github.com/keeperlink/request-info-docker/blob/master/.github/workflows/docker-build.yml).

Before the first release, create the public Docker Hub repository
`keeperlink/ssh-mcp`. In GitHub **Settings → Environments**, create an
environment named `dockerhub-publish`. Set **Deployment branches and tags**
to **Selected branches and tags** and add **only** the branch `main` (no
wildcards, tags or other branches). Then add two *environment secrets* there:

- `DOCKERHUB_USERNAME` — the Docker Hub account with push access
- `DOCKERHUB_TOKEN` — a Docker Hub access token with push permission

Do **not** use repository-level secrets: those are accessible to other
branches' workflows. Remove or rotate any earlier repository-level Docker
Hub credentials after moving them into the restricted environment.
The environment must be configured before the first dispatch; a workflow
can otherwise auto-create an unprotected environment.

Do not put credentials in workflow files or build arguments.

To publish, choose **Actions → Publish Docker Hub image → Run workflow** on
`main`. A successful current `main` CI run is required. The workflow builds
the final image (including its mandatory installed-wheel tests), smoke-tests
an isolated container with synthetic credentials, and logs in only afterward.

BuildKit exports one OCI archive with SBOM and provenance. The smoke test
loads its runnable image from a temporary Docker-format archive. Skopeo
then copies the unchanged OCI index under both Docker Hub tags, requiring
matching SHA-256 digests. The workflow never rebuilds the image.

Each manual run publishes `keeperlink/ssh-mcp:0.1.<run-number>` and updates
`keeperlink/ssh-mcp:latest`. An existing numbered tag cannot be reused by
the workflow. Releases currently target `linux/amd64`; add other platforms
only after validating them.

## Security-maintained base images

The public image builds with **Python 3.12 / Debian 13 (Trixie)** in each
Python build stage, rather than the earlier Debian 12 Bookworm base. Its
runtime layer installs current Debian security updates and the SSH client
from the selected distribution. Both CI and manual publication resolve
the latest official Python base image, even when Buildx caching is enabled.

After each release, scan the **actual published immutable image digest**
with Docker Scout or another vulnerability scanner and compare it with
the previous release. Review fixable high/critical findings and check Debian's
security tracker before treating a scanner result as mitigated. Moving to
Trixie does **not** resolve every SQLite, Kerberos, or other outstanding CVE;
do not claim zero vulnerabilities based only on a successful Docker build.
Image publication remains manual and subject to successful main-branch CI.

The published image includes the Apache-2.0 license and third-party notices,
OCI source/revision/version labels, SBOM, and BuildKit provenance attestations.
Use the versioned tag or resolved digest for deployments, and keep a known-good
image digest for rollback. This procedure does not deploy SSH-MCP to any host.
