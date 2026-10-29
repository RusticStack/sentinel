#!/usr/bin/env python3
"""Verify a Sentinel release manifest (sentinel.release/1) against the files it names.

    python3 -I scripts/release/verify-manifest.py release-manifest.json [--dir DIR] [--pins pins.env]

Exits 0 when every check passes and 1 after printing every failure; 2 for bad usage.
Checks (docs/releasing.md#the-release-manifest):
  * the schema is exactly "sentinel.release/1" (an unknown version is refused, not guessed at);
  * every artifact in the manifest is present in DIR with the listed size and SHA-256;
  * every bundled helper's executable inside its package has the listed SHA-256;
  * with --pins, the helper digests equal the ones pinned in scripts/release/pins.env.
Standard library only.
"""
import hashlib
import json
import os
import re
import sys
import tarfile

SCHEMA = "sentinel.release/1"
KINDS = {"server", "worker", "cli", "agent"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_pins(path):
    pins = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                pins[key] = value
    return pins


def verify(manifest_path, directory, pins_path):
    errors = []

    def fail(message):
        errors.append(message)

    try:
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as error:
        return [f"{manifest_path}: cannot read manifest: {error}"]
    if not isinstance(manifest, dict):
        return ["manifest is not a JSON object"]
    schema = manifest.get("schema")
    if schema != SCHEMA:
        return [f"unknown manifest version {schema!r}: this verifier reads only {SCHEMA!r}"]
    if not isinstance(manifest.get("version"), str) or not manifest["version"]:
        fail("version is missing")
    if not isinstance(manifest.get("commit"), str) or not HEX40.match(manifest["commit"]):
        fail("commit is not 40 hex digits")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        fail("artifacts is missing or empty")
        artifacts = []
    helpers = manifest.get("helpers", [])
    if not isinstance(helpers, list):
        fail("helpers is not a list")
        helpers = []

    by_package = {}
    for entry in artifacts:
        if not isinstance(entry, dict):
            fail("an artifact entry is not an object")
            continue
        name = entry.get("file")
        if not isinstance(name, str) or not name or os.path.basename(name) != name:
            fail(f"artifact file {name!r} is not a plain file name")
            continue
        if entry.get("kind") not in KINDS:
            fail(f"{name}: unknown kind {entry.get('kind')!r}")
        for key in ("os", "arch"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                fail(f"{name}: {key} is missing")
        sha = entry.get("sha256")
        size = entry.get("bytes")
        if not isinstance(sha, str) or not HEX64.match(sha):
            fail(f"{name}: sha256 is not 64 hex digits")
            continue
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            fail(f"{name}: bytes is not a size")
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            fail(f"{name}: missing from {directory}")
            continue
        if os.path.getsize(path) != size:
            fail(f"{name}: {os.path.getsize(path)} bytes on disk, manifest says {size}")
        actual = sha256_file(path)
        if actual != sha:
            fail(f"{name}: sha256 mismatch (manifest {sha}, file {actual})")
        by_package[(entry.get("kind"), entry.get("os"), entry.get("arch"))] = (name, path)

    pins = read_pins(pins_path) if pins_path else None
    for helper in helpers:
        if not isinstance(helper, dict):
            fail("a helper entry is not an object")
            continue
        name, arch = helper.get("name"), helper.get("arch")
        label = f"helper {name} {helper.get('version')} {arch}"
        sha = helper.get("sha256")
        if not all(isinstance(v, str) and v for v in (name, arch, helper.get("version"))):
            fail(f"{label}: name, version and arch are required")
            continue
        if not isinstance(sha, str) or not HEX64.match(sha):
            fail(f"{label}: sha256 is not 64 hex digits")
            continue
        if not isinstance(helper.get("license"), str) or not helper["license"]:
            fail(f"{label}: license is missing")
        if pins is not None:
            key = f"{name.upper()}_{arch.upper()}_SHA256"
            if name == "kernel":
                key = "KERNEL_SHA256"
            if pins.get(key) != sha:
                fail(f"{label}: sha256 {sha} is not the pinned {key} {pins.get(key)!r}")
        package, inner = helper.get("package"), helper.get("path")
        if package is None:
            continue  # named, not bundled (Tailcat): the digest is what an installer checks
        found = by_package.get((package, "linux", arch))
        if found is None:
            fail(f"{label}: package {package}/{arch} is not among the verified artifacts")
            continue
        file_name, file_path = found
        member = file_name[: -len(".tar.gz")] + "/" + str(inner)
        try:
            with tarfile.open(file_path, "r:gz") as archive:
                handle = archive.extractfile(member)
                if handle is None:
                    fail(f"{label}: {member} is not a file in {file_name}")
                    continue
                digest = hashlib.sha256()
                for block in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(block)
        except KeyError:
            fail(f"{label}: {member} is missing from {file_name}")
            continue
        except (OSError, tarfile.TarError) as error:
            fail(f"{label}: cannot read {file_name}: {error}")
            continue
        if digest.hexdigest() != sha:
            fail(f"{label}: {member} has sha256 {digest.hexdigest()}, manifest says {sha}")
    return errors


def main(argv):
    args = argv[1:]
    manifest = directory = pins = None
    while args:
        arg = args.pop(0)
        if arg == "--dir" and args:
            directory = args.pop(0)
        elif arg == "--pins" and args:
            pins = args.pop(0)
        elif manifest is None and not arg.startswith("--"):
            manifest = arg
        else:
            print(__doc__, file=sys.stderr)
            return 2
    if manifest is None:
        print(__doc__, file=sys.stderr)
        return 2
    directory = directory or os.path.dirname(os.path.abspath(manifest))
    errors = verify(manifest, directory, pins)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if not errors:
        print(f"ok  {manifest}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
