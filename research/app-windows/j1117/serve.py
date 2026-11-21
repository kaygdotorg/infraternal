#!/usr/bin/env python3
# Role: tiny local server for the tile-lane flicker replay (#146 proposal C): serves the recording and stores reports.
"""Serve this directory on 127.0.0.1 and write each POSTed report to reports/<name>.json.

Usage: serve.py <port> <seconds>. Exits when a report named "done" arrives or after <seconds>. Standard library only.
"""
import http.server, os, sys, threading, urllib.parse

class Handler(http.server.SimpleHTTPRequestHandler):
    """Static files plus POST /report?name=... ."""
    def do_POST(self):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        name = os.path.basename(query.get("name", ["report"])[0])
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        os.makedirs("reports", exist_ok=True)
        with open(os.path.join("reports", name + ".json"), "wb") as f:
            f.write(body)
        self.send_response(204); self.end_headers()
        if name == "done":
            # Exit at once: the page has posted everything it will post.
            os._exit(0)
    def end_headers(self):
        # Module workers and fetches need no special headers; disable caching so reruns see new files.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()
    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
threading.Timer(float(sys.argv[2]), server.shutdown).start()
server.serve_forever()
