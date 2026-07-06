#!/usr/bin/env python3
# COOP/COEP static server for arch/wasm headless runs (SharedArrayBuffer requires
# cross-origin isolation). Referenced by run-node-verifier-v1.mjs.
import sys, http.server, socketserver

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8200

class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()
    def guess_type(self, path):
        if path.endswith(".wasm"):
            return "application/wasm"
        return super().guess_type(path)

with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    print(f"serving on {PORT}", flush=True)
    httpd.serve_forever()
