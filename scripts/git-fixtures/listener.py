#!/usr/bin/env python3
"""Records what the G08 fixtures' post-receive hooks deliver.

The fixtures configure the shipped hook with an intake URL on this listener, so a push exercises
the hook's real path (`curl`, spool, delivery id) with no controller involved. Every request is
appended to one JSON object per line: method, path, headers and body. Nothing is validated here;
`run.sh exercise` reads the file and checks the delivery.

    python3 listener.py --out FILE --bind 127.0.0.1 [--bind ADDRESS ...] --port PORT

A Docker bridge reaches the host only through its gateway address, so the caller binds that too.
"""

import argparse
import http.server
import json
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        record = {
            "at_ms": round(time.time() * 1000),
            "method": "POST",
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf8", "replace"),
        }
        with self.server.lock:
            with open(self.server.out, "a", encoding="utf8") as f:
                f.write(json.dumps(record) + "\n")
        reply = b'{"accepted":true}'
        self.send_response(202)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bind", action="append", default=[])
    args = parser.parse_args()
    servers = []
    lock = threading.Lock()
    for address in args.bind or ["127.0.0.1"]:
        server = Server((address, args.port), Handler)
        server.out = args.out
        server.lock = lock
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(" ".join(f"{s.server_address[0]}:{s.server_address[1]}" for s in servers), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
