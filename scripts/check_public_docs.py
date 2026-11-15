#!/usr/bin/env python3
'''Offline safety and Markdown-link checks for public Compose examples.

No Docker daemon, SSH target, network, or private credentials are accessed.
'''
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from pathlib import Path
import re
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from uvicorn.config import Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
SAMPLES = ROOT / 'examples' / 'standalone'
BASIC = ROOT / 'examples' / 'basic'
HARDENED = ROOT / 'examples' / 'hardened'
REQUIRED = {
    'getting-started.md', 'configuration.md', 'oauth-clients.md',
    'security.md', 'commands-jobs.md', 'operator-console.md',
    'file-operations.md', 'patch-workflows.md', 'operations.md',
    'troubleshooting.md', 'reverse-proxies.md', 'hardening.md',
    'upgrade-compatibility.md',
}


def env_example(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise ValueError(f'Invalid sample line in {path.name}')
        key, value = line.split('=', 1)
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*', key) or key in values:
            raise ValueError(f'Invalid or repeated sample key: {key}')
        values[key] = value
    return values


def validate() -> None:
    assert REQUIRED.issubset({p.name for p in DOCS.glob('*.md')})
    assert not list(DOCS.glob('SKY-*.md')), 'Obsolete numbered documents remain'
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    assert len(readme.splitlines()) <= 150, 'Product README is too long'

    # Validate local links against the actual new files; reject escapes.
    for doc in [ROOT / 'README.md', ROOT / 'ops' / 'README.md', *DOCS.glob('*.md')]:
        body = doc.read_text(encoding='utf-8')
        assert 'docs/SKY-' not in body, f'Obsolete docs link: {doc.name}'
        assert not re.search(r'\]\s*\n\s*\(', body), (
            f'{doc.relative_to(ROOT)}: split Markdown link target')
        for raw in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)', body):
            path = unquote(raw.split('#', 1)[0])
            if not path or re.match(r'^[a-z]+://', path):
                continue
            resolved = (doc.parent / path).resolve()
            assert resolved.is_relative_to(ROOT) and resolved.is_file(), (
                f'{doc.relative_to(ROOT)}: missing or unsafe link {raw}'
            )

    # Public startup examples must explicitly allow their configured HTTPS
    # Host, rather than trusting a hardcoded private domain by default.
    example = env_example(BASIC / "service.env.example")
    issuer = urlsplit(example["MCP_ISSUER"])
    hosts = set(example["MCP_ALLOWED_HOSTS"].split(","))
    assert issuer.scheme == "https" and issuer.hostname in hosts
    assert f"{issuer.hostname}:{issuer.port or 443}" in hosts
    assert "localhost" in hosts

    migration = (DOCS / 'upgrade-compatibility.md').read_text(encoding='utf-8')
    for must_document in ('SSH_JOBS_DB', 'jobs.database',
                          'fresh,', 'same retained database',
                          'previous environment intact'):
        assert must_document in migration, ('Missing upgrade instruction: ' +
                                            must_document)

    inventory = json.loads((SAMPLES / 'inventory.json.example').read_text())
    assert json.loads((BASIC / 'inventory.json.example').read_text()) == inventory
    assert inventory['version'] == 1 and len(inventory['hosts']) == 1
    host = inventory['hosts'][0]
    assert host['alias'] == 'demo'
    assert host['access'] == 'restricted'
    assert host['privileged_access'] == 'none'
    assert host['principals'] == ['ssh-mcp-operator']
    assert host['identity_file'] == '/run/ssh-mcp/identity'
    assert host['known_hosts_file'] == '/run/ssh-mcp/known_hosts'
    assert host['address'].endswith('.example.net')
    assert not (SAMPLES / 'known_hosts').exists()

    service = env_example(SAMPLES / 'service.env.example')
    assert env_example(BASIC / 'service.env.example') == service
    site = env_example(SAMPLES / 'site.env.example')
    basic_site = env_example(BASIC / 'site.env.example')
    hardened_site = env_example(HARDENED / 'site.env.example')
    assert basic_site == hardened_site, 'Basic/hardened bridge configuration must match'
    assert site['MCP_PUBLIC_HOST'] == 'mcp.example.com'
    subnet = ipaddress.ip_network(site['MCP_PROXY_SUBNET'], strict=True)
    dynamic_pool = ipaddress.ip_network(site['MCP_PROXY_DYNAMIC_RANGE'], strict=True)
    caddy_ip = ipaddress.ip_address(site['MCP_CADDY_IP'])
    assert subnet.version == dynamic_pool.version == caddy_ip.version == 4
    assert subnet.is_private
    assert caddy_ip in subnet and caddy_ip != subnet.network_address
    assert caddy_ip != subnet.broadcast_address
    assert dynamic_pool.subnet_of(subnet) and dynamic_pool.num_addresses >= 4
    assert caddy_ip not in dynamic_pool, "Caddy's fixed IP cannot be assigned dynamically"
    assert service['MCP_ISSUER'] == 'https://' + site['MCP_PUBLIC_HOST']
    assert service['SSH_APPROVED_ALIASES'] == host['alias']
    assert service['SSH_INVENTORY_FILE'] == '/run/ssh-mcp/inventory.json'
    assert service['SSH_JOBS_ENABLED'] == 'true'
    assert service['MCP_METRICS_ENABLED'] == 'false'
    assert service['MCP_CIMD_VALIDATE_REMOTE'] == 'true'
    assert all(service[key] == 'REPLACE_ME' for key in (
        'MCP_LOGIN_KEY', 'MCP_TOKEN_SIGNING_SECRET', 'HISTORY_VIEWER_PASSWORD'
    )), 'Demo credentials must fail runtime startup'
    assert 'SSH_JOBS_RETENTION_SECONDS' not in service
    # Existing HTTPS proxy variants must not expose cleartext app HTTP publicly.
    app_subnet = ipaddress.ip_network(basic_site['MCP_BRIDGE_SUBNET'], strict=True)
    app_gateway = ipaddress.ip_address(basic_site['MCP_DOCKER_GATEWAY'])
    assert app_subnet.version == app_gateway.version == 4 and app_subnet.is_private
    assert app_gateway in app_subnet
    assert app_gateway not in (app_subnet.network_address, app_subnet.broadcast_address)
    # Loopback port isolation was fixed in Docker Engine 28.0.0; old
    # daemons can expose even a localhost binding to same-L2 peers.
    readme = (ROOT / 'README.md').read_text()
    first_run = (DOCS / 'getting-started.md').read_text()
    proxy_docs = (DOCS / 'reverse-proxies.md').read_text()
    hardening_docs = (DOCS / 'hardening.md').read_text()
    assert all('28.0.0' in content for content in (
        readme, first_run, proxy_docs, hardening_docs
    )), 'Basic/hardened must document Docker Engine 28.0.0+'
    assert "docker version --format '{{.Server.Version}}'" in first_run
    assert 'https://docs.docker.com/engine/network/port-publishing/' in first_run
    for dirname, variant in ((BASIC, 'basic'), (HARDENED, 'hardened')):
        app_compose = (dirname / 'compose.yaml').read_text()
        assert '28.0.0' in app_compose, 'Per-example minimum Engine version missing'
        assert '127.0.0.1:${MCP_LOCAL_PORT:-8000}:8000' in app_compose
        assert 'FORWARDED_ALLOW_IPS: "${MCP_DOCKER_GATEWAY:?Set bridge gateway IP}"' in app_compose
        assert 'gateway: "${MCP_DOCKER_GATEWAY:?Set bridge gateway IP}"' in app_compose
        assert 'subnet: "${MCP_BRIDGE_SUBNET:?Set unused bridge subnet}"' in app_compose
        assert 'user: "10001:10001"' in app_compose
        assert 'read_only: true' in app_compose  # SSH inputs, mandatory.
        assert 'mcp-state:/var/lib/ssh-mcp' in app_compose
        assert '80:80' not in app_compose and '443:443' not in app_compose
        assert 'caddy:' not in app_compose and 'docker.sock' not in app_compose
        if variant == 'hardened':
            for hardening in ('cap_drop: [ALL]', 'read_only: true',
                              'no-new-privileges:true', 'pids_limit: 128',
                              'mem_limit: 512m', '/tmp:rw,noexec,nosuid,size=16m'):
                assert hardening in app_compose, hardening
        else:
            assert 'cap_drop: [ALL]' not in app_compose
    assert not any(key in service for key in (
        'MCP_CONFIG_FILE', 'MCP_INVENTORY_FILE',
        'MCP_KNOWN_HOSTS_FILE', 'MCP_SECRETS_FILE'
    )), 'Do not enter managed issuer-locked configuration mode'

    compose = (SAMPLES / 'compose.yaml').read_text()
    mcp = compose.split('\n  https:\n', 1)[0]
    assert '\n    ports:\n' not in mcp, 'Internal MCP HTTP must not have host ports'
    for expected in (
        'user: "10001:10001"', 'read_only: true', 'cap_drop: [ALL]',
        'no-new-privileges:true', 'mcp-state', '/run/ssh-mcp',
        'MCP_PRIVATE_ENV', 'MCP_SSH_CONFIG_DIR',
    ):
        assert expected in mcp, f'Missing container protection {expected}'
    assert '"80:80"' in compose and '"443:443"' in compose
    assert 'docker.sock' not in compose
    assert 'FORWARDED_ALLOW_IPS: "${MCP_CADDY_IP:?Set exact private Caddy IP}"' in compose
    assert 'ipv4_address: "${MCP_CADDY_IP:?Set exact private Caddy IP}"' in compose
    assert 'subnet: "${MCP_PROXY_SUBNET:?Set unused private subnet}"' in compose
    assert 'ip_range: "${MCP_PROXY_DYNAMIC_RANGE:?Set pool excluding Caddy IP}"' in compose
    caddy = (SAMPLES / 'Caddyfile').read_text()
    assert 'admin off' in caddy and 'reverse_proxy mcp:8000' in caddy
    assert 'header_up X-Forwarded-For {remote_host}' in caddy
    allowed = next(line for line in caddy.splitlines() if '@public path ' in line)
    assert all(name in allowed for name in ('/mcp', '/oauth/*', '/console/*'))
    assert all(name not in allowed for name in ('/ready', '/health', '/metrics'))
    assert 'respond "Not found" 404' in caddy
    # Verify both proxy designs trust exactly one peer, never an arbitrary
    # forwarded header from another Docker bridge participant.
    for peer, network in ((caddy_ip, subnet), (app_gateway, app_subnet)):
        observed: list[str] = []

        async def app(scope, receive, send):
            observed.append(scope['client'][0])

        with patch.dict(os.environ, {'FORWARDED_ALLOW_IPS': str(peer)}):
            config = Config(app=app, access_log=False)
        assert config.forwarded_allow_ips == str(peer)
        trusted = ProxyHeadersMiddleware(app, trusted_hosts=config.forwarded_allow_ips)
        other_address = ipaddress.ip_address(int(peer) + 1)
        other_ip = str(other_address)
        assert other_address in network and other_address != peer

        async def verify_forwarding():
            for source, claimed_ip in (
                (str(peer), '198.51.100.11'),
                (str(peer), '198.51.100.12'),
                (other_ip, '198.51.100.99'),
            ):
                scope = {
                    'type': 'http', 'client': (source, 42318), 'scheme': 'http',
                    'headers': [(b'x-forwarded-for', claimed_ip.encode('ascii')),
                                (b'x-forwarded-proto', b'https')],
                }
                await trusted(scope, None, None)

        asyncio.run(verify_forwarding())
        assert observed == ['198.51.100.11', '198.51.100.12', other_ip], observed
    print('Public links, basic/Caddy/hardened Compose and exact-peer proxy trust: PASS')


if __name__ == '__main__':
    validate()
