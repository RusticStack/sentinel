# The G08 bare-repository fixture: an sshd with `git` on it, nothing else.
#
#   podman build -t sentinel-g08-ssh-git -f bench/g08/ssh-git.Containerfile bench/g08
#
# Rootless Podman maps the container's root to the verification account, so the
# bare repository the container serves is the one on the host's disk and its
# hooks reach the fixture's own loopback. It is a fixture on loopback only:
# key-only authentication, no password, no shell beyond git's.
FROM docker.io/library/alpine:3.20

RUN apk add --no-cache git openssh-server openssh-client curl \
    && ssh-keygen -A \
    && mkdir -p /git /root/.ssh \
    && chmod 700 /root/.ssh

COPY ssh-git-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2222
ENTRYPOINT ["/entrypoint.sh"]
