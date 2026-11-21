#!/usr/bin/env bash
# Build the runner-mode image and publish it, then print the reference a worker pins
# (docs/runner-mode.md#the-runner-image-and-its-update-policy).
#
#   scripts/release/publish-runner-image.sh ghcr.io/rusticstack/sentinel-runner
#   scripts/release/publish-runner-image.sh 127.0.0.1:5000/sentinel/sentinel-runner --tls-verify=false
#
# The digest it prints is the only reference a worker accepts under [runner] image; a tag is refused,
# because the same tag is another image tomorrow and this one is the code a job's steps run under. The
# version comes from the Containerfile, so the tag and the image's own label cannot disagree.
#
# RUNNER_IMAGE=ubuntu-2404 publishes the image with toolchains instead
# (examples/Containerfile.runner-ubuntu-2404, docs/runner-images.md): the runner image is built first and
# stays local, and the toolset image is built on it, checks its own toolset as its last build step, and is
# the one pushed. Name a repository of its own for it:
#
#   RUNNER_IMAGE=ubuntu-2404 scripts/release/publish-runner-image.sh ghcr.io/rusticstack/sentinel-runner-ubuntu-2404
#
# PUBLISH=0 builds and checks without pushing, which is what a pull request's build does.
#
# PODMAN_BUILD_OPTIONS passes extra flags to the build, for a host whose build needs them (a container
# without slirp needs `--network=host`, and one without a systemd user session needs its engine's
# cgroup manager set to cgroupfs).
#
# Run it on each architecture that serves runner mode (x86_64 and arm64); every architecture publishes
# its own digest, and an operator pins the one their workers run. Publish before a worker names it: the
# sandbox pulls never, so a worker that states a digest it does not hold declines every runner lease.
#
# After it prints the digest, the sandbox suite becomes a real gate rather than a skip:
#
#   podman pull <reference>
#   SENTINEL_PODMAN_TESTS=1 SENTINEL_RUNNER_IMAGE=<reference> \
#     cargo nextest run --locked -p sentinel-worker --all-features --test runner_sandbox
set -euo pipefail

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$root"

command -v podman >/dev/null || { echo "podman is not installed" >&2; exit 1; }
[ $# -ge 1 ] || { echo "usage: publish-runner-image.sh <registry/repository> [podman push options…]" >&2; exit 2; }
repository=${1%/}
shift

containerfile=examples/Containerfile.runner
version=$(sed -n 's/^ARG RUNNER_VERSION=\(.*\)$/\1/p' "$containerfile")
[ -n "$version" ] || { echo "$containerfile states no RUNNER_VERSION" >&2; exit 1; }

digestfile=$(mktemp)
trap 'rm -f "$digestfile"' EXIT

flavor=${RUNNER_IMAGE:-runner}
echo "building $repository:$version (actions/runner $version, $flavor)" >&2
case $flavor in
  runner)
    # Deliberately unquoted: the variable carries flags, and an empty value must expand to nothing.
    # shellcheck disable=SC2086
    podman build ${PODMAN_BUILD_OPTIONS:-} -f "$containerfile" -t "$repository:$version" .
    ;;
  ubuntu-2404)
    base="localhost/sentinel-runner-base:$version"
    # shellcheck disable=SC2086
    podman build ${PODMAN_BUILD_OPTIONS:-} -f "$containerfile" -t "$base" .
    # shellcheck disable=SC2086
    podman build ${PODMAN_BUILD_OPTIONS:-} -f examples/Containerfile.runner-ubuntu-2404       --build-arg "RUNNER=$base" -t "$repository:$version" .
    ;;
  *)
    echo "RUNNER_IMAGE is '$flavor': runner or ubuntu-2404" >&2
    exit 2
    ;;
esac
built=$(podman inspect --format '{{index .Config.Labels "io.sentinel.runner.version"}}' "$repository:$version")
[ "$built" = "$version" ] || {
  echo "the image states runner $built, the Containerfile pins $version" >&2
  exit 1
}

if [ "${PUBLISH:-1}" = 0 ]; then
  echo "built $repository:$version; PUBLISH=0, so nothing was pushed" >&2
  exit 0
fi

podman push --digestfile "$digestfile" "$@" "$repository:$version" >&2
reference="$repository@$(cat "$digestfile")"
echo "a worker pins this line:" >&2
echo "image = \"$reference\""
