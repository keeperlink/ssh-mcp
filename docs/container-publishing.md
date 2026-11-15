# Publishing to Docker Hub

SSH-MCP uses the same manual, test-before-publish approach as
[request-info-docker](https://github.com/keeperlink/request-info-docker/blob/master/.github/workflows/docker-build.yml).

Before the first release, create the public Docker Hub repository
`keeperlink/ssh-mcp` and configure these **repository secrets** under
GitHub Settings → Secrets and variables → Actions:

- `DOCKERHUB_USERNAME` — the Docker Hub account with push access
- `DOCKERHUB_TOKEN` — a Docker Hub access token with the required push permission

Do not put credentials in workflow files or build arguments.

To publish, choose **Actions → Publish Docker Hub image → Run workflow** on
`main`. A successful current `main` CI run is required. The workflow builds
the final image (including its mandatory installed-wheel tests), smoke-tests
an isolated container with synthetic credentials, and logs in only afterward.

Each manual run publishes `keeperlink/ssh-mcp:0.1.<run-number>` and updates
`keeperlink/ssh-mcp:latest`. An existing numbered tag cannot be reused by
the workflow. Releases currently target `linux/amd64`; add other platforms
only after validating them.

The published image includes the Apache-2.0 license and third-party notices,
OCI source/revision/version labels, SBOM, and BuildKit provenance attestations.
Use the versioned tag or resolved digest for deployments, and keep a known-good
image digest for rollback. This procedure does not deploy SSH-MCP to any host.
