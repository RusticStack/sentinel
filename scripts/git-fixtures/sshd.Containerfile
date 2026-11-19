# G08 fixture: a bare repository behind its own sshd, without root and without a forge.
#
# The repository, its hook and the authorized key are created inside the container (a named
# volume), so nothing here depends on how the runtime maps uids onto the host file system.
FROM docker.io/library/alpine@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

RUN apk add --no-cache git openssh-server curl \
 && adduser -D -u 1000 -s /usr/bin/git-shell git \
 && passwd -d git \
 && echo /usr/bin/git-shell >> /etc/shells \
 && mkdir -p /srv/git /run/sshd /etc/fixture \
 && chown git:git /srv/git

COPY sshd.conf /etc/fixture/sshd.conf
COPY sshd-entrypoint.sh /usr/local/bin/sshd-entrypoint
RUN chmod 755 /usr/local/bin/sshd-entrypoint

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/sshd-entrypoint"]
