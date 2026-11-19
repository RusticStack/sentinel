#!/bin/sh
# Generates the fixture's host key on first start, then serves the bare repository over SSH.
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
exec /usr/sbin/sshd -D -e -f /etc/fixture/sshd.conf
