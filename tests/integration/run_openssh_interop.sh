#!/usr/bin/env bash
# TEST-265 opt-in native interoperability with the project-owned OpenSSH fixture.
# Requires rootless Docker on an explicitly approved development host.
# Does not run the separately pinned lab runner or touch shared services.
set -euo pipefail
umask 077

repo="$(git rev-parse --show-toplevel)"
docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless' || {
    echo 'REJECTED: test requires rootless Docker' >&2
    exit 3
}
private="$(mktemp -d /tmp/ssh-mcp-interop.XXXXXXXX)"
suffix="$(printf '%s' "$private" | sha256sum | cut -c1-12)"
network="ssh-mcp-interop-net-$suffix"
container="ssh-mcp-interop-sshd-$suffix"
fixture_image="ssh-mcp-interop-sshd:$suffix"
client_image="ssh-mcp-interop-client:$suffix"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    docker image rm "$fixture_image" "$client_image" >/dev/null 2>&1 || true
    rm -rf -- "$private"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$private/identity"
python3 -c 'import secrets; print(secrets.token_urlsafe(25))' > "$private/sudo-password"
chmod 0600 "$private/identity" "$private/sudo-password"

# Build only the requested fixture and installed-wheel application runtime.
docker build --quiet -t "$fixture_image" "$repo/tests/lab/fixture" >/dev/null
docker build --quiet --target runtime -t "$client_image" "$repo" >/dev/null
docker network create --internal --driver bridge "$network" >/dev/null
docker run -d --name "$container" --network "$network" \
    --network-alias ssh-mcp-interop-sshd \
    --mount "type=bind,source=$private/sudo-password,target=/run/fixture-sudo-password,readonly" \
    -e "SSH_AUTHORIZED_KEY=$(cat "$private/identity.pub")" \
    "$fixture_image" >/dev/null

ready=0
for _ in $(seq 1 50); do
    if docker exec "$container" sh -c \
        'test -s /etc/ssh/ssh_host_ed25519_key.pub && pgrep -x sshd >/dev/null' \
        >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep .2
done
test "$ready" -eq 1 || {
    echo 'OPENSSH_FIXTURE=NOT_READY' >&2
    docker logs --tail 12 "$container" >&2
    exit 2
}
docker exec "$container" cat /etc/ssh/ssh_host_ed25519_key.pub |
    awk '{print "ssh-mcp-interop-sshd "$1" "$2}' > "$private/known_hosts"
chmod 0644 "$private/known_hosts"
echo 'OPENSSH_FIXTURE=READY; ISOLATED_NETWORK=YES; PUBLISHED_PORTS=NONE'

# Both containers share only a private internal Docker network; no host ports.
# Keys are per-run; only the client sees the private key and sudo password.
docker run --rm --network "$network" --user 0:0 --read-only \
    --tmpfs /tmp:rw,nosuid,size=16m \
    --mount "type=bind,source=$private,target=/keys,readonly" \
    --mount "type=bind,source=$repo/tests/integration/openssh_interop.py,target=/opt/test.py,readonly" \
    --entrypoint python3 "$client_image" /opt/test.py
echo 'NATIVE_OPENSSH_INTEROP=PASS'
