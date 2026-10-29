import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HELPER = os.path.join(os.path.dirname(__file__), "seed-membership.py")
USER = "usr_00000000-0000-4000-8000-000000000001"


def serve(script):
    """A controller stand-in that records every request and answers from `script` (method, path) -> (status, body)."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_any(self):
            length = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(length) or b"null")
            seen.append((self.command, self.path, body, {k.lower(): v for k, v in self.headers.items()}))
            status, reply = script.get((self.command, self.path), (404, {"code": "not_found"}))
            raw = json.dumps(reply).encode()
            self.send_response(status)
            if self.path.endswith("/login") and status == 200:
                self.send_header("set-cookie", "__Host-sentinel_session=abc; HttpOnly; Secure; Path=/")
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_POST = do_PUT = handle_any

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, seen


def run(server, *extra, password="pw-of-the-admin"):
    return subprocess.run(
        [sys.executable, "-I", HELPER, "--api", f"http://127.0.0.1:{server.server_port}/api/v1",
         "--username", "root", *extra],
        input=password, capture_output=True, text=True,
    )


class Seed(unittest.TestCase):
    def test_signs_in_steps_up_and_adds_the_admin_to_each_tenant_with_a_reason(self):
        script = {
            ("POST", "/api/v1/login"): (200, {"user": USER, "csrf": "tok"}),
            ("POST", "/api/v1/step-up"): (200, {"stepped_up": True}),
            ("PUT", f"/api/v1/tenants/acme/members/{USER}"): (200, {}),
            ("PUT", f"/api/v1/tenants/beta/members/{USER}"): (200, {}),
            ("POST", "/api/v1/logout"): (200, {"ok": True}),
        }
        server, seen = serve(script)
        done = run(server, "--tenant", "acme", "--tenant", "beta", "--reason", "seed one")
        server.shutdown()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(
            [(m, p) for m, p, _, _ in seen],
            [("POST", "/api/v1/login"), ("POST", "/api/v1/step-up"),
             ("PUT", f"/api/v1/tenants/acme/members/{USER}"),
             ("PUT", f"/api/v1/tenants/beta/members/{USER}"), ("POST", "/api/v1/logout")],
        )
        self.assertEqual(seen[0][2], {"username": "root", "password": "pw-of-the-admin"})
        self.assertEqual(seen[1][2], {"method": "password", "code": "pw-of-the-admin"})
        for _, _, body, headers in seen[1:]:
            self.assertEqual(headers.get("cookie"), "__Host-sentinel_session=abc")
            self.assertEqual(headers.get("x-sentinel-csrf"), "tok")
        self.assertEqual(seen[2][2], {"role": "admin", "reason": "seed one"})
        self.assertNotIn("pw-of-the-admin", done.stdout + done.stderr)

    def test_a_refused_step_up_fails_and_nothing_is_written(self):
        script = {
            ("POST", "/api/v1/login"): (200, {"user": USER, "csrf": "tok"}),
            ("POST", "/api/v1/step-up"): (403, {"code": "forbidden"}),
        }
        server, seen = serve(script)
        done = run(server, "--tenant", "acme")
        server.shutdown()
        self.assertEqual(done.returncode, 1)
        self.assertIn("step-up failed", done.stderr)
        self.assertFalse([1 for m, _, _, _ in seen if m == "PUT"])

    def test_a_refused_membership_fails_the_run(self):
        script = {
            ("POST", "/api/v1/login"): (200, {"user": USER, "csrf": "tok"}),
            ("POST", "/api/v1/step-up"): (200, {"stepped_up": True}),
            ("PUT", f"/api/v1/tenants/acme/members/{USER}"): (400, {"code": "invalid_request"}),
        }
        server, _ = serve(script)
        done = run(server, "--tenant", "acme")
        server.shutdown()
        self.assertEqual(done.returncode, 1)
        self.assertIn("membership in acme failed: HTTP 400 invalid_request", done.stderr)


if __name__ == "__main__":
    unittest.main()
