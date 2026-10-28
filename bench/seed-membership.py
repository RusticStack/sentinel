#!/usr/bin/env python3
"""Make a platform administrator a member of tenants the way the API allows it.

A platform administrator has no ambient access to a tenant's repositories, runs or queue; joining a tenant
needs a browser-style session, a fresh step-up and a stated reason, and the change is audited as a
`platform-override` row (docs/authorization.md, docs/step-up.md). No host-local command adds the
administrator to a tenant on its behalf, and a benchmark must not write the `memberships` row itself:
that skips the audit row and the tenant's authorization epoch. This helper walks the supported path
against a running controller:

  POST /login -> POST /step-up (password) -> PUT /tenants/{slug}/members/{user} {role, reason} -> POST /logout

  printf '%s' "$PASSWORD" | seed-membership.py --api http://127.0.0.1:PORT/api/v1 \\
      --username root --tenant acme [--tenant beta ...] [--role admin] [--reason TEXT]

The password is read from standard input and never printed. Repeating the call is harmless.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def call(method, url, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    if data is not None:
        request.add_header("content-type", "application/json")
    try:
        with OPENER.open(request, timeout=30) as reply:
            return reply.status, dict(reply.headers), json.loads(reply.read() or b"null")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw or b"null")
        except ValueError:
            parsed = None
        return error.code, dict(error.headers), parsed


def fail(step, status, body):
    code = body.get("code") if isinstance(body, dict) else None
    print(f"seed-membership: {step} failed: HTTP {status} {code or ''}".rstrip(), file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--api", required=True, help="the API base, ending in /api/v1")
    parser.add_argument("--username", required=True)
    parser.add_argument("--tenant", action="append", required=True, help="tenant slug (repeatable)")
    parser.add_argument("--role", default="admin", choices=["reader", "operator", "admin"])
    parser.add_argument("--reason", default="benchmark seed")
    args = parser.parse_args()
    password = sys.stdin.read()
    api = args.api.rstrip("/")

    status, headers, body = call("POST", f"{api}/login", {"username": args.username, "password": password})
    if status != 200:
        fail("login", status, body)
    cookie = next(v for k, v in headers.items() if k.lower() == "set-cookie").split(";")[0]
    session = {"cookie": cookie, "x-sentinel-csrf": body["csrf"]}
    user = body["user"]

    status, _, reply = call("POST", f"{api}/step-up", {"method": "password", "code": password}, session)
    if status != 200:
        fail("step-up", status, reply)
    for slug in args.tenant:
        status, _, reply = call(
            "PUT", f"{api}/tenants/{slug}/members/{user}", {"role": args.role, "reason": args.reason}, session
        )
        if status != 200:
            fail(f"membership in {slug}", status, reply)
    call("POST", f"{api}/logout", {}, session)
    print(f"{user} is {args.role} of {', '.join(args.tenant)}", file=sys.stderr)


if __name__ == "__main__":
    main()
