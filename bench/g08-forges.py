"""The G08 forge fixtures: Gitea, Forgejo, GitLab and a bare repository behind sshd, as containers.

    python3 bench/g08-forges.py up {gitea|forgejo|gitlab|bare|all}
    python3 bench/g08-forges.py status
    python3 bench/g08-forges.py down [name ...]
    python3 bench/g08-forges.py converge NAME     # print the bindings the controller needs
    python3 bench/g08-forges.py selftest

Every fixture listens on loopback only, so a push through its hook reaches a
controller on the same host. The scripts are idempotent: `up` replaces a fixture
that already exists and `down` forgets it.

What each fixture creates, matching docs/generic-git-verification.md:

    gitea    ci/app over HTTPS (local CA) and over Gitea's built-in SSH, `gitea-app`
             and `gitea-app-ssh`; a second repository `ci/app2` for the poll lane;
             `other/foreign` owned by a second user; the post-receive hook under
             Gitea's managed hooks directory.
    forgejo  ci/app over HTTPS, `forgejo-app`, same hook location.
    gitlab   root/gitlab-app over SSH, `gitlab-app`, hook under Gitaly's
             custom_hooks. Refused when the host has less than 6 GiB of memory.
    bare     a bare repository behind an sshd container, `bare-app`, plain
             hooks/post-receive.

The state directory is `SENTINEL_G08_DIR` (default /var/tmp/sentinel-g08). It
holds the CA and its keys, each fixture's data volume, the deploy keys and the
hook environment. Nothing in it is a measurement and nothing is committed.

No third-party Python packages. Linux x86_64 or aarch64; rootless Podman is
preferred and rootful Docker is the fallback.
"""
import argparse
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

STATE = os.environ.get("SENTINEL_G08_DIR", "/var/tmp/sentinel-g08")
NETWORK = "sentinel-g08"
HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "hooks", "post-receive")
PASSWORD_FILE = "password"

# Ports are fixed so a binding can be written down: they are the ones
# docs/generic-git-verification.md names.
PORTS = {
    "gitea": {"https": 3443, "ssh": 3022},
    "forgejo": {"https": 3444, "ssh": 3024},
    "gitlab": {"https": 3445, "ssh": 3023},
    "bare": {"ssh": 2222},
}

IMAGES = {
    "gitea": "docker.io/gitea/gitea:1.27.3",
    "forgejo": "codeberg.org/forgejo/forgejo:9",
    "gitlab": "docker.io/gitlab/gitlab-ce:18.3.2-ce.0",
    "bare": "sentinel-g08-ssh-git",
}

# What each fixture needs before it can be useful, so a refusal happens before
# an image is pulled rather than after ten minutes of waiting.
NEEDS = {
    "gitea": {"memory_gib": 1},
    "forgejo": {"memory_gib": 1},
    "gitlab": {"memory_gib": 6},
    "bare": {"memory_gib": 0},
}


class FixtureError(Exception):
    pass


def ensure_runtime_dir():
    """Rootless Podman wants XDG_RUNTIME_DIR (it mounts its network namespace under it). A verification
    account reached without a login session has none, so give it the conventional one when it can."""
    if os.environ.get("XDG_RUNTIME_DIR"):
        return
    uid = os.getuid()
    candidate = f"/run/user/{uid}"
    try:
        os.makedirs(candidate, mode=0o700, exist_ok=True)
        os.chmod(candidate, 0o700)
    except PermissionError:
        return
    os.environ["XDG_RUNTIME_DIR"] = candidate


def runtime():
    """The container runtime this host offers: rootless Podman first, Docker second."""
    ensure_runtime_dir()
    for name in ("podman", "docker"):
        if shutil.which(name):
            return name
    raise FixtureError("neither podman nor docker is on PATH")


def run(argv, **kw):
    kw.setdefault("check", True)
    kw.setdefault("stdout", subprocess.PIPE)
    kw.setdefault("stderr", subprocess.PIPE)
    kw.setdefault("text", True)
    try:
        return subprocess.run(argv, **kw)
    except FileNotFoundError as error:
        raise FixtureError(f"{argv[0]} is not installed") from error
    except subprocess.CalledProcessError as error:
        # Only the tail: a failed pull prints megabytes, and the line an operator needs is the last one.
        detail = (error.stderr or "").strip().splitlines()
        raise FixtureError(f"{' '.join(argv[:3])} failed: {(detail[-1] if detail else 'no output')}") from error


def state(*parts):
    path = os.path.join(STATE, *parts)
    os.makedirs(path, exist_ok=True)
    return path


def memory_gib():
    """The host's memory, so a fixture that needs more is refused instead of thrashing."""
    with open("/proc/meminfo", encoding="utf8") as handle:
        for line in handle:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // (1024 * 1024)
    return 0


def free_disk_gib(path=None):
    """The free space under the state directory's file system, without relying on `df`."""
    root = path or (os.path.dirname(STATE) if os.path.isdir(os.path.dirname(STATE)) else "/")
    stat = os.statvfs(root)
    return (stat.f_bavail * stat.f_frsize) // (1024 ** 3)


def preflight(name):
    """Everything a fixture needs, checked before anything is pulled or created."""
    if name not in IMAGES:
        raise FixtureError(f"unknown fixture {name}; one of {', '.join(IMAGES)}")
    need = NEEDS[name]
    have = memory_gib()
    if have < need["memory_gib"]:
        raise FixtureError(
            f"{name} needs at least {need['memory_gib']} GiB of memory; this host has {have} GiB"
        )
    if free_disk_gib() < 8:
        raise FixtureError(f"{name} needs 8 GiB of free disk under {STATE}; this host has less")
    if not shutil.which("openssl"):
        raise FixtureError("openssl is required to mint the fixture CA")
    if not os.path.exists(HELPER):
        raise FixtureError(f"the hook the fixtures install is missing: {HELPER}")
    return runtime()


def container_name(name):
    return f"sentinel-g08-{name}"


def exists(name):
    found = run([runtime(), "ps", "-a", "--filter", f"name=^{container_name(name)}$",
                 "--format", "{{.Names}}"], check=False)
    return found.returncode == 0 and found.stdout.strip() == container_name(name)


def down_one(name):
    if exists(name):
        run([runtime(), "rm", "-f", container_name(name)], check=False)
    return f"{name}: removed"


def network():
    run([runtime(), "network", "create", NETWORK], check=False)
    return NETWORK


def ca():
    """A fixture CA and one leaf for 127.0.0.1 and localhost, reused across runs."""
    directory = os.path.join(state(), "ca")
    os.makedirs(directory, exist_ok=True)
    key, cert = os.path.join(directory, "ca.key"), os.path.join(directory, "ca.crt")
    leaf_key, leaf = os.path.join(directory, "fixture.key"), os.path.join(directory, "fixture.crt")
    if not os.path.exists(leaf):
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", key, "-out", cert, "-subj", "/CN=sentinel-g08-fixture-ca",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", leaf_key,
             "-out", os.path.join(directory, "leaf.csr"), "-subj", "/CN=127.0.0.1"])
        _sign(cert, key, leaf, directory)
    # The fixture containers run as their own unprivileged user, not as the account that minted these, so
    # the leaf has to be readable by them. It is a two-day loopback certificate for a disposable fixture.
    for path in (cert, leaf, leaf_key):
        os.chmod(path, 0o644)
    return cert, leaf, leaf_key


def _sign(cert, key, leaf, directory):
    ext = os.path.join(directory, "leaf.ext")
    with open(ext, "w", encoding="utf8") as handle:
        handle.write("subjectAltName=IP:127.0.0.1,DNS:localhost\n"
                     "basicConstraints=critical,CA:FALSE\n"
                     "keyUsage=critical,digitalSignature,keyEncipherment\n"
                     "extendedKeyUsage=serverAuth\n")
    run(["openssl", "x509", "-req", "-in", os.path.join(directory, "leaf.csr"),
         "-CA", cert, "-CAkey", key, "-CAcreateserial", "-days", "2", "-out", leaf,
         "-extfile", ext])


def password(fixture):
    """A generated credential per fixture, on disk at mode 0600 and never printed."""
    directory = state(fixture)
    path = os.path.join(directory, PASSWORD_FILE)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf8") as handle:
            handle.write(secrets.token_urlsafe(24))
        os.chmod(path, 0o600)
    with open(path, encoding="utf8") as handle:
        return handle.read()


def deploy_key(fixture):
    """An ed25519 key pair for the fixture's SSH surface, generated once."""
    directory = state(fixture)
    private, public = os.path.join(directory, "deploy_key"), os.path.join(directory, "deploy_key.pub")
    if not os.path.exists(private):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"sentinel-{fixture}", "-f", private])
        os.chmod(private, 0o600)
    with open(public, encoding="utf8") as handle:
        return private, handle.read().strip()


def hook_env(fixture, intake_url, hook_secret):
    """The hook environment a fixture installs beside its post-receive, owner-only."""
    directory = state(fixture)
    path = os.path.join(directory, "sentinel-hook.env")
    with open(path, "w", encoding="utf8") as handle:
        handle.write(f"SENTINEL_INTAKE_URL={intake_url}\nSENTINEL_HOOK_SECRET={hook_secret}\n")
    os.chmod(path, 0o600)
    return path


def up_ssh_forge(name):
    """Gitea and Forgejo share one shape: HTTPS with the fixture CA plus their own SSH server."""
    preflight(name)
    cert, leaf, leaf_key = ca()
    directory = state(name)
    ports = PORTS[name]
    down_one(name)
    network()
    # Host networking, so a push's hook reaches a controller on the same loopback exactly as the page
    # describes: the controller, the worker and the fixtures share one loopback. The forge then binds the
    # fixture's own ports instead of having them published to it.
    env = [
        "-e", "GITEA__server__PROTOCOL=https",
        "-e", "GITEA__server__CERT_FILE=/certs/fixture.crt",
        "-e", "GITEA__server__KEY_FILE=/certs/fixture.key",
        "-e", "GITEA__server__ROOT_URL=https://127.0.0.1:%d/" % ports["https"],
        "-e", "GITEA__server__HTTP_PORT=%d" % ports["https"],
        "-e", "GITEA__server__SSH_DOMAIN=127.0.0.1",
        "-e", "GITEA__server__SSH_PORT=%d" % ports["ssh"],
        "-e", "GITEA__server__START_SSH_SERVER=true",
        "-e", "GITEA__server__SSH_LISTEN_PORT=%d" % ports["ssh"],
        "-e", "GITEA__security__INSTALL_LOCK=true",
        "-e", "GITEA__service__DISABLE_REGISTRATION=true",
        "-e", "GITEA__database__DB_TYPE=sqlite3",
    ]
    if name == "forgejo":
        # Forgejo reads the same configuration keys through FORGEJO__ variables.
        env = [item.replace("GITEA__", "FORGEJO__") for item in env]
    run([runtime(), "run", "-d", "--name", container_name(name), "--network", "host",
         "-v", f"{directory}:/data", "-v", f"{os.path.dirname(cert)}:/certs:ro", *env,
         IMAGES[name]])
    wait_https(ports["https"])
    # The forge runs as its own unprivileged user, and its CLI refuses to run as root, so the administration
    # calls go through that user.
    admin = [runtime(), "exec", "--user", "git", container_name(name), "gitea"]
    run(admin + ["admin", "user", "create", "--admin", "--username", "ci",
                 "--password", password(name), "--email", "ci@fixture.invalid",
                 "--must-change-password=false"], check=False)
    setup = run(admin + ["admin", "user", "generate-access-token", "--username", "ci",
                         "--token-name", "setup-" + secrets.token_hex(4), "--scopes", "all", "--raw"],
                check=False).stdout.strip()
    api = Api(f"https://127.0.0.1:{ports['https']}", cert, setup)
    for repo in ("app", "app2"):
        api.post("/api/v1/user/repos", {"name": repo, "private": False}, already_there=409)
    binding = run(admin + ["admin", "user", "generate-access-token", "--username", "ci",
                           "--token-name", "sentinel-" + secrets.token_hex(4), "--scopes", "read:repository",
                           "--raw"], check=False).stdout.strip()
    # The push credential belongs to the person driving the fixture, never to the binding: a verification
    # run pushes with this one and binds the read-only token above.
    pushing = run(admin + ["admin", "user", "generate-access-token", "--username", "ci",
                           "--token-name", "push-" + secrets.token_hex(4), "--scopes", "write:repository",
                           "--raw"], check=False).stdout.strip()
    write_token(name, pushing, "push_token")
    # The forge copies its global hooks into a repository when that repository is created, so the hook goes
    # in first and then into every repository a previous run may have made.
    global_hook = "/data/gitea/hooks/post-receive.d/sentinel"
    install_hook(name, global_hook)
    for repo in ("app", "app2"):
        install_hook(name, f"/data/git/repositories/ci/{repo}.git/hooks/post-receive.d/sentinel")
    return {"fixture": name, "https": f"https://127.0.0.1:{ports['https']}",
            "ssh": f"ssh://git@127.0.0.1:{ports['ssh']}", "ca": cert,
            "token_file": write_token(name, binding)}


class Api:
    """The fixture's own API over its CA, for the provisioning the forges' CLIs cannot do."""

    def __init__(self, base, ca_path, token):
        import ssl
        self.base, self.token = base.rstrip("/"), token
        self.context = ssl.create_default_context(cafile=ca_path)

    def post(self, path, body, already_there=None):
        request = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(),
            headers={"authorization": f"token {self.token}", "content-type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=20) as answer:
                return json.loads(answer.read() or b"{}")
        except urllib.error.HTTPError as error:
            if already_there is not None and error.code == already_there:
                return {}
            raise FixtureError(f"{path}: {error.code} {error.read()[:200].decode('utf8', 'replace')}")


def install_hook(fixture, container_path):
    """Puts the shipped post-receive where the forge runs it. The forge's data volume belongs to its own
    user, so the hook goes in through the runtime rather than through this account's file system."""
    name = container_name(fixture)
    directory = container_path.rsplit("/", 1)[0]
    run([runtime(), "exec", "--user", "git", name, "mkdir", "-p", directory])
    # `cp` keeps the source's mode and the forge's own user cannot chmod a file it does not own, so the
    # executable bit is set on the copy that goes in.
    staged = os.path.join(state(fixture), "post-receive")
    shutil.copy(HELPER, staged)
    os.chmod(staged, 0o755)
    run([runtime(), "cp", staged, f"{name}:{container_path}"])
    # The runtime's own user is root in the container, which is what may change a file it copied in.
    run([runtime(), "exec", name, "chmod", "0755", container_path])
    return container_path


def write_token(fixture, token, name="token"):
    directory = state(fixture)
    path = os.path.join(directory, name)
    if token:
        with open(path, "w", encoding="utf8") as handle:
            handle.write(token)
        os.chmod(path, 0o600)
    return path


def up_gitlab():
    preflight("gitlab")
    cert, leaf, leaf_key = ca()
    ports = PORTS["gitlab"]
    down_one("gitlab")
    network()
    run([runtime(), "run", "-d", "--name", container_name("gitlab"), "--network", NETWORK,
         "-p", f"127.0.0.1:{ports['ssh']}:22",
         "-e", "GITLAB_OMNIBUS_CONFIG=external_url 'https://127.0.0.1:%d'; "
               "nginx['redirect_http_to_https']=false; nginx['listen_https']=false; "
               "gitlab_rails['gitlab_shell_ssh_port']=%d" % (ports['https'], ports["ssh"]),
         "-v", f"{state('gitlab')}:/var/opt/gitlab",
         "-v", f"{os.path.dirname(cert)}:/certs:ro", IMAGES["gitlab"]])
    return {"fixture": "gitlab", "ssh": f"ssh://git@127.0.0.1:{ports['ssh']}",
            "ssh_port": ports["ssh"]}


def ssh_git_image():
    """The fixture image: sshd with git on it, built once from bench/g08/ssh-git.Containerfile."""
    tag = "sentinel-g08-ssh-git"
    built = run([runtime(), "image", "exists", tag], check=False)
    if built.returncode == 0:
        return tag
    context = os.path.join(os.path.dirname(os.path.abspath(__file__)), "g08")
    run([runtime(), "build", "-t", tag, "-f", os.path.join(context, "ssh-git.Containerfile"), context],
        stdout=subprocess.DEVNULL)
    return tag


def up_bare():
    preflight("bare")
    directory = state("bare")
    repos = os.path.join(directory, "repos")
    os.makedirs(repos, exist_ok=True)
    bare = os.path.join(repos, "app.git")
    if not os.path.exists(bare):
        run(["git", "init", "--bare", "-q", bare])
        hook = os.path.join(bare, "hooks", "post-receive")
        shutil.copy(HELPER, hook)
        os.chmod(hook, 0o755)
    private, public = deploy_key("bare")
    authorized = os.path.join(directory, "authorized_keys")
    with open(authorized, "w", encoding="utf8") as handle:
        handle.write(public + "\n")
    os.chmod(authorized, 0o600)
    down_one("bare")
    image = ssh_git_image()
    # Host networking for the same reason: the hook inside the container has to reach a controller on the
    # fixture's own loopback.
    run([runtime(), "run", "-d", "--name", container_name("bare"), "--network", "host",
         "-e", "G08_PUBLIC_KEY=" + public,
         "-v", f"{repos}:/git:Z",
         image])
    wait_port(PORTS["bare"]["ssh"])
    return {"fixture": "bare", "ssh": f"ssh://git@127.0.0.1:{PORTS['bare']['ssh']}/git/app.git",
            "deploy_key": private}


UP = {"gitea": lambda: up_ssh_forge("gitea"), "forgejo": lambda: up_ssh_forge("forgejo"),
      "gitlab": up_gitlab, "bare": up_bare}


def wait_port(port, seconds=90):
    """Waits until something answers on the port, so `up` returns a usable fixture or fails."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        probe = subprocess.run(["bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{port}"],
                               capture_output=True)
        if probe.returncode == 0:
            return
        time.sleep(0.5)
    raise FixtureError(f"nothing answers on 127.0.0.1:{port} after {seconds}s")


def wait_https(port, seconds=180):
    """Waits until the fixture answers over HTTPS with its own CA."""
    cert, _, _ = ca()
    context = __import__("ssl").create_default_context(cafile=cert)
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"https://127.0.0.1:{port}/api/v1/version",
                                        context=context, timeout=5) as answer:
                if answer.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    raise FixtureError(f"127.0.0.1:{port} did not answer over HTTPS after {seconds}s")


def converge(name):
    """The binding a controller needs for this fixture, in the shape `sentinel admin source` takes."""
    if name not in PORTS:
        raise FixtureError(f"unknown fixture {name}")
    directory = state(name)
    if name in ("gitea", "forgejo"):
        return {
            "repo": f"{name}-app",
            "https": f"https://127.0.0.1:{PORTS[name]['https']}/ci/app.git",
            "ssh": f"{name}-app-ssh",
            "ssh_url": f"ssh://git@127.0.0.1:{PORTS[name]['ssh']}/ci/app.git",
            "ca": os.path.join(directory, "..", "ca", "ca.crt"),
            "token_file": os.path.join(directory, "token"),
            "hook": "post-receive.d/sentinel",
        }
    if name == "bare":
        return {
            "repo": "bare-app",
            "ssh_url": f"ssh://git@127.0.0.1:{PORTS['bare']['ssh']}/git/app.git",
            "deploy_key": os.path.join(directory, "deploy_key"),
            "hook": "hooks/post-receive",
        }
    return {
        "repo": "gitlab-app",
        "ssh_url": f"ssh://git@127.0.0.1:{PORTS['gitlab']['ssh']}/root/gitlab-app.git",
        "hook": "custom_hooks/post-receive",
    }


def bind(name, intake_url, secret_file):
    """Tells the fixture's hook where to deliver. The secret is read from a file so it never reaches argv,
    and the hook environment is written owner-only beside every post-receive the fixture runs."""
    if name not in PORTS:
        raise FixtureError(f"unknown fixture {name}")
    try:
        with open(secret_file, encoding="utf8") as handle:
            secret = handle.read().strip()
    except OSError as error:
        raise FixtureError(f"cannot read the hook secret: {error}") from error
    if not secret:
        raise FixtureError(f"{secret_file} is empty")
    staged = os.path.join(state(name), "sentinel-hook.env")
    # The hook spools an event before its first attempt, so it needs a directory its own user may write: a
    # forge's hook directory is not one.
    spool = "/data/git/sentinel-intake" if name in ("gitea", "forgejo") else os.path.join(state("bare"), "spool")
    with open(staged, "w", encoding="utf8") as handle:
        handle.write(f"SENTINEL_INTAKE_URL={intake_url}\nSENTINEL_HOOK_SECRET={secret}\n"
                     f"SENTINEL_SPOOL_DIR={spool}\n")
    os.chmod(staged, 0o600)
    placed = []
    if name in ("gitea", "forgejo"):
        run([runtime(), "exec", "--user", "git", container_name(name), "mkdir", "-p", spool], check=False)
        for path in ["/data/gitea/hooks/post-receive.d/sentinel-hook.env",
                     "/data/git/repositories/ci/app.git/hooks/post-receive.d/sentinel-hook.env",
                     "/data/git/repositories/ci/app2.git/hooks/post-receive.d/sentinel-hook.env"]:
            run([runtime(), "cp", staged, f"{container_name(name)}:{path}"], check=False)
            # The hook runs as the forge's own user and the copy arrives owned by the container's root, so the
            # environment is handed to that user and kept owner-only.
            run([runtime(), "exec", container_name(name), "chown", "git:git", path], check=False)
            run([runtime(), "exec", container_name(name), "chmod", "0600", path], check=False)
            placed.append(path)
    else:
        os.makedirs(spool, exist_ok=True)
        with open(os.path.join(state("bare"), "repos", "app.git", "hooks", "sentinel-hook.env"), "w",
                  encoding="utf8") as handle:
            handle.write(open(staged, encoding="utf8").read())
        os.chmod(os.path.join(state("bare"), "repos", "app.git", "hooks", "sentinel-hook.env"), 0o600)
        placed.append("app.git/hooks/sentinel-hook.env")
    return {"fixture": name, "intake_url": intake_url, "placed": placed}


def status():
    rows = []
    for name in IMAGES:
        rows.append({"fixture": name, "running": exists(name),
                     "ports": PORTS[name], "image": IMAGES[name]})
    return rows


def selftest():
    """The checks that need no container: the refusal paths and the binding shape."""
    failures = []
    try:
        preflight("nonexistent")
        failures.append("an unknown fixture was accepted")
    except FixtureError as error:
        if "unknown fixture" not in str(error):
            failures.append(f"an unknown fixture failed for the wrong reason: {error}")
    saved = dict(os.environ)
    try:
        os.environ["PATH"] = "/nonexistent"
        for name in ("gitea", "gitlab", "bare"):
            try:
                preflight(name)
            except FixtureError:
                pass
            else:
                failures.append(f"{name} was accepted with no runtime on PATH")
    finally:
        os.environ.clear()
        os.environ.update(saved)
    for name in IMAGES:
        binding = converge(name)
        if "repo" not in binding or "hook" not in binding:
            failures.append(f"{name}'s binding is incomplete: {binding}")
    if NEEDS["gitlab"]["memory_gib"] <= NEEDS["gitea"]["memory_gib"]:
        failures.append("GitLab's memory need is not above Gitea's")
    return failures


def main(argv):
    parser = argparse.ArgumentParser(description="G08 forge fixtures")
    parser.add_argument("command", choices=["up", "down", "status", "converge", "bind", "selftest"])
    parser.add_argument("names", nargs="*")
    args = parser.parse_args(argv)
    try:
        if args.command == "selftest":
            failures = selftest()
            for failure in failures:
                print(f"FAIL {failure}")
            print("PASS g08 fixtures" if not failures else "FAIL g08 fixtures")
            return 0 if not failures else 1
        if args.command == "status":
            print(json.dumps(status(), indent=2))
            return 0
        if args.command == "bind":
            if len(args.names) != 3:
                raise FixtureError("bind takes NAME INTAKE_URL SECRET_FILE")
            print(json.dumps(bind(*args.names), indent=2))
            return 0
        if args.command == "converge":
            for name in args.names or list(IMAGES):
                print(json.dumps(converge(name), indent=2))
            return 0
        if args.command == "down":
            for name in args.names or list(IMAGES):
                print(down_one(name))
            return 0
        for name in args.names or ["all"]:
            for one in (list(IMAGES) if name == "all" else [name]):
                started = time.time()
                print(json.dumps({**UP[one](), "up_s": round(time.time() - started, 1)}, indent=2))
        return 0
    except FixtureError as error:
        print(f"g08-forges: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
