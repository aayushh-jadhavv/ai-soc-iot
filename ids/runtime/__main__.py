"""Local worker and release management. Run python -m ids.runtime --help."""

import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import threading

from ids.runtime.bundle import MODEL_ID, canonical, pack, valid_version
from ids.runtime.server import Server
from ids.runtime.worker import Worker


class Control(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            command = self.rfile.readline(256).decode().strip()
            if command == "rollback":
                self.server.worker.activate(rollback=True)
            elif command.startswith("activate "):
                self.server.worker.activate(valid_version(command.removeprefix("activate ")))
            else:
                raise ValueError("Expected activate MODEL_ID or rollback")
            reply = dict(active=self.server.worker.bundle.model_id, epoch=self.server.worker.epoch)
        except Exception as exc:
            reply = dict(error=str(exc)[:512])
        self.wfile.write(canonical(reply))


def serve(args):
    args.state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.state.stat().st_mode & 0o077:
        raise ValueError("Worker state directory must be private (chmod 700)")
    token = args.token_file.read_text().strip()
    if not token or not token.isascii() or any(c.isspace() for c in token):
        raise ValueError("Expected a nonempty ASCII bearer token")
    sock = args.state / "control.sock"
    with ExitStack() as stack:
        lock = stack.enter_context((args.state / "worker.lock").open("a"))
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        worker = Worker(args.releases, args.state / "activation.json")
        stack.callback(worker.executor.shutdown)
        server = stack.enter_context(Server(args.port, worker, token))
        sock.unlink(missing_ok=True)
        stack.callback(sock.unlink, missing_ok=True)
        control = stack.enter_context(socketserver.UnixStreamServer(str(sock), Control))
        control.worker = worker
        def restore():
            try:
                worker.activate(worker.state["active"] or MODEL_ID)
                print(f"Ready: {worker.bundle.model_id}", flush=True)
            except Exception as exc:
                print(f"Initial bundle unavailable: {exc}", flush=True)

        def manage():
            restore()
            control.serve_forever()

        thread = threading.Thread(target=manage, daemon=True)
        print(f"IDS worker listening on 127.0.0.1:{server.server_port}", flush=True)
        thread.start()
        stack.callback(thread.join)
        stack.callback(control.shutdown)
        server.serve_forever()


def main():
    data = Path(os.getenv("IOT_DATA_DIR", Path.home() / ".local/share/iot-gateway"))
    token = Path(os.getenv("IOT_IDS_TOKEN_FILE", data / "ids-token"))
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    build = sub.add_parser("pack")
    build.add_argument("--run", type=Path, default=Path("experiments/phase6/run-001"))
    build.add_argument("--releases", type=Path, default=Path("models/phase7"))
    init = sub.add_parser("init-token")
    init.add_argument("--token-file", type=Path, default=token)
    run = sub.add_parser("serve")
    run.add_argument("--port", type=int, default=8000)
    run.add_argument("--releases", type=Path, default=Path("models/phase7"))
    run.add_argument("--token-file", type=Path, default=token)
    activate = sub.add_parser("activate")
    activate.add_argument("model_id", type=valid_version)
    rollback = sub.add_parser("rollback")
    for command in (run, activate, rollback):
        command.add_argument("--state", type=Path, default=data / "ids-worker")
    args = p.parse_args()
    if args.command == "pack":
        print(pack(args.run, args.releases))
    elif args.command == "init-token":
        args.token_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(args.token_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write(secrets.token_urlsafe(32) + "\n")
        print(f"Created {args.token_file}")
    elif args.command == "serve":
        serve(args)
    else:
        message = "rollback" if args.command == "rollback" else "activate " + args.model_id
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(args.state / "control.sock"))
            client.sendall((message + "\n").encode())
            with client.makefile("rb") as stream:
                result = json.load(stream)
        if "error" in result:
            p.exit(1, result["error"] + "\n")
        print(json.dumps(result))


if __name__ == "__main__":
    main()
