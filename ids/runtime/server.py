"""Loopback JSON service with bounded HTTP and inference concurrency."""

import hmac
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ids.runtime.bundle import canonical
from ids.runtime.worker import problem


class Server(ThreadingHTTPServer):
    def __init__(self, port, worker, token):
        self.worker = worker
        self.credential = b"Bearer " + token.encode("ascii")
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(("127.0.0.1", port), Handler)

    def process_request(self, request, address):
        request.settimeout(1.0)
        self.slots.acquire()
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def object_pairs(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate JSON field")
    return obj


class Handler(BaseHTTPRequestHandler):
    def handle(self):
        self.deadline = time.monotonic() + 1
        def end_read():
            try:
                self.connection.shutdown(socket.SHUT_RD)
            except OSError:
                pass

        timer = threading.Timer(1, end_read)
        timer.daemon = True
        timer.start()
        try:
            super().handle()
        except (TimeoutError, ConnectionError):
            pass
        finally:
            timer.cancel()

    def log_message(self, *args):
        pass

    def reply(self, response, epoch=None):
        code, data = response
        encoded = canonical(data)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        if epoch:
            self.send_header("X-IDS-History-Epoch", epoch)
        self.end_headers()
        self.wfile.write(encoded)

    def authorized(self):
        values = self.headers.get_all("Authorization", [])
        if len(values) == 1 and hmac.compare_digest(values[0].encode("latin-1"), self.server.credential):
            return True
        self.reply(problem("UNAUTHORIZED", "Service credential required"))
        return False

    def do_GET(self):
        if not self.authorized():
            return
        if self.path not in ("/v1/health", "/v1/metadata"):
            self.send_error(404)
            return
        self.reply(*self.server.worker.info(self.path == "/v1/health"))

    def do_POST(self):
        if not self.authorized():
            return
        if self.path != "/v1/predict":
            self.send_error(404)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get_content_type() != "application/json" or "Transfer-Encoding" in self.headers
                or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0])
                or not 0 < int(lengths[0]) <= 262144):
            self.reply(problem("INVALID_INPUT", "Expected a bounded JSON request with Content-Length"))
            return
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            self.connection.settimeout(remaining)
            body = self.rfile.read(int(lengths[0]))
            if time.monotonic() >= self.deadline:
                raise TimeoutError
            if len(body) != int(lengths[0]):
                raise ValueError
            request = json.loads(body.decode("utf-8"), object_pairs_hook=object_pairs)
        except TimeoutError:
            self.reply(problem("DEADLINE_EXCEEDED", "Request deadline elapsed"))
            return
        except (ValueError, RecursionError):
            self.reply(problem("INVALID_INPUT", "Malformed JSON body"))
            return
        self.reply(*self.server.worker.predict(request, self.deadline))
