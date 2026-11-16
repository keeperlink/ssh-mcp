# Single reviewed OCI image for self-hosted and separately managed deployments.
# Cache runtime dependencies independently of app source changes.
# pyproject.toml is the ONLY dependency source of truth; avoid maintaining
# another requirements file that could diverge from the shipped wheel.
FROM python:3.12-slim-trixie AS dependency-wheels
WORKDIR /src
COPY pyproject.toml ./
RUN python -c "import tomllib; from pathlib import Path; data=tomllib.loads(Path('pyproject.toml').read_text()); Path('/runtime-requirements.txt').write_text(chr(10).join(data['project']['dependencies']) + chr(10))" \
    && python -m pip wheel --disable-pip-version-check --no-cache-dir --wheel-dir=/dependency-wheels -r /runtime-requirements.txt

# App-only wheel build: changing app/* does not invalidate dependency wheels.
FROM python:3.12-slim-trixie AS application-wheel
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY app/ ./app/
RUN python -m pip wheel --disable-pip-version-check --no-cache-dir --no-deps --wheel-dir=/application-wheel .

FROM python:3.12-slim-trixie AS runtime-base
# Apply stable-security fixes to both the Python base and required SSH libraries.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 mcp && useradd --no-create-home -u 10001 -g 10001 mcp \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/ssh-mcp
COPY --from=dependency-wheels /dependency-wheels /dependency-wheels
COPY --from=dependency-wheels /runtime-requirements.txt /runtime-requirements.txt
RUN python -m pip install --no-index --find-links=/dependency-wheels --no-cache-dir -r /runtime-requirements.txt \
    && rm -rf /dependency-wheels /runtime-requirements.txt

FROM runtime-base AS runtime
# The source, wheel and OCI image share one Apache-2.0 license.
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY LICENSE /usr/local/share/licenses/ssh-mcp/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/local/share/licenses/ssh-mcp/THIRD_PARTY_NOTICES.md
# The image builder may supply APP_VERSION and BUILD_NUMBER with the immutable tag.
# A local CI build without those args retains an empty (undisplayed) version.
ARG APP_VERSION=""
ARG BUILD_NUMBER=""
RUN python -c 'import os,re,sys; from pathlib import Path; prefix=os.environ.get("APP_VERSION",""); number=os.environ.get("BUILD_NUMBER",""); assert (not prefix and not number) or (re.fullmatch(r"[0-9]+(?:\.[0-9]+)*",prefix) and re.fullmatch(r"[1-9][0-9]{0,8}",number)), "Invalid image version arguments"; version=f"{prefix}.{number}" if prefix else ""; path=Path(sys.argv[1]); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(version)' /usr/local/share/ssh-mcp/version
COPY --from=application-wheel /application-wheel /application-wheel
RUN python -m pip install --no-index --no-deps --find-links=/application-wheel --no-cache-dir ssh-mcp \
    && rm -rf /application-wheel
COPY ops/history_db.py /usr/local/bin/ssh-mcp-history-db
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp MCP_BIND_HOST=0.0.0.0 MCP_BIND_PORT=8000
USER 10001:10001
WORKDIR /var/lib/ssh-mcp
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=3     CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/ready',timeout=3).close()"
CMD ["python", "-m", "app"]


# Verify the *installed runtime wheel* against the exact Python and runtime
# dependencies used by the deployable image. This stage is a mandatory build
# dependency of final, not an optional --target selected by the image producer.
FROM runtime AS runtime-tests
USER root
RUN python -m pip install --disable-pip-version-check --no-cache-dir --no-deps coverage==7.17.0 \
    && install -d -m 0755 -o 10001 -g 10001 /validation
COPY --chown=10001:10001 tests/ /validation/tests/
COPY --chown=10001:10001 scripts/check_coverage.py /validation/scripts/check_coverage.py
COPY --chown=10001:10001 ops/history_db.py /validation/ops/history_db.py
COPY --chown=10001:10001 deploy/service.example.json /validation/deploy/service.example.json
COPY --chown=10001:10001 examples/basic/compose.yaml /validation/examples/basic/compose.yaml
COPY --chown=10001:10001 examples/hardened/compose.yaml /validation/examples/hardened/compose.yaml
COPY --chown=10001:10001 Dockerfile VERSION LICENSE THIRD_PARTY_NOTICES.md /validation/
COPY --chown=10001:10001 pyproject.toml /validation/pyproject.toml
COPY --chown=10001:10001 .github/workflows/ci.yml /validation/.github/workflows/ci.yml
COPY --chown=10001:10001 .github/workflows/docker-publish.yml /validation/.github/workflows/docker-publish.yml
COPY --chown=10001:10001 docs/container-publishing.md /validation/docs/container-publishing.md
COPY --chown=10001:10001 docs/getting-started.md /validation/docs/getting-started.md
USER 10001:10001
WORKDIR /validation
RUN python -m pip check \
    && python -c "from pathlib import Path; import app; assert '/site-packages/' in str(Path(app.__file__).resolve()), 'Tests must import the installed production wheel'" \
    && MCP_ISSUER=http://localhost MCP_RESOURCE=http://localhost/mcp MCP_CIMD_VALIDATE_REMOTE=false \
       MCP_LOGIN_KEY=synthetic-test-login-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
       MCP_TOKEN_SIGNING_SECRET=synthetic-test-signing-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
       python -m coverage run tests/tools/run_unit_tests.py \
    && python -m coverage json -o /validation/coverage.json \
    && python scripts/check_coverage.py /validation/coverage.json --min 95

# Copy an existing runtime-owned executable from the successful test stage.
# BuildKit MUST execute runtime-tests to produce final, even with warm caches.
# No test sources, test dependencies or coverage reports enter this image.
FROM runtime AS final
COPY --from=runtime-tests /usr/local/bin/ssh-mcp-history-db /usr/local/bin/ssh-mcp-history-db
