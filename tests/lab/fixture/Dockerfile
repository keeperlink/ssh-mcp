# Disposable SSH integration target; no host ports, real hosts or persistent state.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server python3 ca-certificates sudo \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1000 --shell /bin/sh tester \
 && mkdir -p /run/sshd /home/tester/.ssh \
 && chown -R tester:tester /home/tester/.ssh \
 && chmod 0700 /home/tester/.ssh \
 && printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin no' 'AllowUsers tester' 'AllowTcpForwarding no' 'AllowAgentForwarding no' 'X11Forwarding no' 'PermitTunnel no' >> /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
