"""Read-only LAN exercise for the Raspberry Pi. Python 3.8+."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "app/src/main/assets/reports.json"


def handler_for(fixture):
    """Serve a fixed snapshot so the phone and bundled fixtures match."""
    health = {
        "schema_version": fixture["schema_version"],
        "gateway_id": fixture["gateway_id"],
        "data_source": "synthetic",
        "status": "ok",
    }
    routes = {
        "/demo/health": health,
        "/demo/report": {
            **{key: fixture[key] for key in health if key != "status"},
            **fixture["reports"][0],
        },
        "/demo/reports": fixture,
    }

    class DemoHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            data = routes.get(self.path)
            status = 200 if data is not None else 404
            body = json.dumps(data if data is not None else {"error": "Unknown route"}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return DemoHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Use the Pi's LAN IPv4 for phone access.")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    with ThreadingHTTPServer((args.host, args.port), handler_for(fixture)) as server:
        print(f"Serving synthetic reports at http://{args.host}:{server.server_port}/demo/health", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
