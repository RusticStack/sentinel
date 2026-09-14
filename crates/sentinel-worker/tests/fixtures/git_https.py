"""Loopback-only smart Git HTTPS fixture. No third-party Python packages."""
import base64
import http.server
import os
import ssl
import subprocess
import sys
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def read_body(self):
        """Decode either Content-Length or chunked framing."""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0], 16)
                if size == 0:
                    self.rfile.readline()
                    return body
                body += self.rfile.read(size)
                self.rfile.read(2)
        size = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(size)

    def handle_git(self):
        with open(os.environ["FIXTURE_PASSWORD"], encoding="utf8") as f:
            password = f.read()
        expected = "Basic " + base64.b64encode(("deploy:" + password).encode()).decode()
        if self.headers.get("Authorization") != expected:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
            self.send_header("Content-Length", str(len(password)))
            self.send_header("Connection", "close")
            self.end_headers()
            # A hostile server may echo secrets. Production errors must not.
            self.wfile.write(password.encode())
            self.close_connection = True
            return
        url = urllib.parse.urlsplit(self.path)
        env = dict(os.environ, GIT_PROJECT_ROOT=sys.argv[1], GIT_HTTP_EXPORT_ALL="1",
                   PATH_INFO=url.path, QUERY_STRING=url.query, REQUEST_METHOD=self.command,
                   CONTENT_TYPE=self.headers.get("Content-Type", ""), REMOTE_USER="deploy")
        body = self.read_body()
        if len(body) > 1024 * 1024:
            self.send_error(413)
            return
        response = subprocess.run(["git", "http-backend"], input=body,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env=env, timeout=10, check=True).stdout
        head, body = response.split(b"\r\n\r\n", 1)
        self.send_response(200)
        for line in head.decode().split("\r\n"):
            key, value = line.split(":", 1)
            self.send_header(key, value.strip())
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    do_GET = handle_git
    do_POST = handle_git


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
