#!/bin/sh
# Entry point of the G08 bare-repository fixture (bench/g08/ssh-git.Containerfile).
#
# G08_PUBLIC_KEY is the deploy key a binding pins; without it the fixture refuses
# to start rather than accepting any key. sshd listens on 2222 in the container,
# which is the fixture's port on the loopback under host networking.
set -eu

: "${G08_PUBLIC_KEY:?the fixture needs G08_PUBLIC_KEY (the deploy key's public half)}"
printf '%s\n' "$G08_PUBLIC_KEY" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

[ -d /git/app.git ] || git init --bare --quiet /git/app.git

install -m 0755 /git/app.git/hooks/post-receive /git/app.git/hooks/post-receive 2>/dev/null || true

cat > /etc/ssh/sshd_config <<'CONF'
Port 2222
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers root
PermitEmptyPasswords no
UseDNS no
PidFile /run/sshd.pid
CONF

exec /usr/sbin/sshd -D -e
