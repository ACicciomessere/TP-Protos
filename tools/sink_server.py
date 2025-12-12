#!/usr/bin/env python3
import socketserver
import http.server
import sys
import errno

class SinkHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        bytes_read = 0
        while bytes_read < length:
            chunk = self.rfile.read(min(65536, length - bytes_read))
            if not chunk:
                break
            bytes_read += len(chunk)

        try:
            self.send_response(200)
            self.end_headers()
            # Mandamos una respuesta mínima
            self.wfile.write(b"OK")
        except BrokenPipeError:
            # El cliente cerró antes de que podamos escribir: lo ignoramos
            pass

    def log_message(self, format, *args):
        # Silenciamos logs para que no ensucien la consola
        return

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

if __name__ == "__main__":
    print("Sink server listening on 127.0.0.1:8888")
    ThreadingHTTPServer(("127.0.0.1", 8888), SinkHandler).serve_forever()
