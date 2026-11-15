#!/bin/sh
set -eu
umask 077
test -n "$SSH_AUTHORIZED_KEY"
case "$SSH_AUTHORIZED_KEY" in ssh-ed25519\ *) ;; *) echo 'Invalid synthetic public key' >&2; exit 2 ;; esac
printf '%s\n' "$SSH_AUTHORIZED_KEY" > /home/tester/.ssh/authorized_keys
chown tester:tester /home/tester/.ssh/authorized_keys
chmod 0600 /home/tester/.ssh/authorized_keys
if [ -f /run/fixture-sudo-password ]; then
    # Only the disposable fixture can read the synthetic per-run credential.
    # PasswordAuth for SSH remains disabled; sudo still requires a password.
    IFS= read -r sudo_password < /run/fixture-sudo-password
    test -n "$sudo_password"
    printf 'tester:%s\n' "$sudo_password" | chpasswd
    unset sudo_password
    printf '%s\n' 'tester ALL=(root) PASSWD: ALL' > /etc/sudoers.d/lab-fixture
    chmod 0440 /etc/sudoers.d/lab-fixture
fi
ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=no
