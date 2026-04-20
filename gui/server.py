#!/usr/bin/env python3
import json
import os
import shlex
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "gui" / "static"
HOST = os.environ.get("SANDBOX_GUI_HOST", "127.0.0.1")
PORT = int(os.environ.get("SANDBOX_GUI_PORT", "8080"))


def run_cmd(args, extra_env=None):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "command": " ".join(shlex.quote(a) for a in args),
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def safe_read(path: Path, max_bytes=512_000):
    if not path.exists():
        return ""
    with path.open("rb") as f:
        data = f.read(max_bytes)
    return data.decode("utf-8", errors="replace")


def list_policies():
    pol_dir = ROOT / "policies"
    if not pol_dir.exists():
        return []
    return sorted([p.name for p in pol_dir.glob("*.json")])


def list_reports():
    rep_dir = ROOT / "reports"
    if not rep_dir.exists():
        return []
    files = sorted(rep_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [p.name for p in files]


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text, status=HTTPStatus.OK, content_type="text/plain; charset=utf-8"):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw) if raw else {}

    def _serve_static(self, name):
        path = STATIC_DIR / name
        if not path.exists() or not path.is_file():
            self._send_text("Not found", HTTPStatus.NOT_FOUND)
            return

        ctype = "text/plain; charset=utf-8"
        if name.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif name.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif name.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"

        self._send_text(safe_read(path), content_type=ctype)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_static("index.html")
            return
        if parsed.path == "/styles.css":
            self._serve_static("styles.css")
            return
        if parsed.path == "/app.js":
            self._serve_static("app.js")
            return

        if parsed.path == "/api/state":
            payload = {
                "policies": list_policies(),
                "reports": list_reports(),
                "log_tail": safe_read(ROOT / "sandbox.log")[-8000:],
                "features": {
                    "syscall_sandbox": True,
                    "policy_loader": True,
                    "network_control": True,
                    "file_access_coarse": True,
                    "logging_monitoring": True,
                    "demo_suite": True,
                    "benchmark": True,
                },
            }
            self._send_json(payload)
            return

        if parsed.path == "/api/report":
            qs = parse_qs(parsed.query)
            name = qs.get("name", [""])[0]
            if not name or "/" in name or ".." in name:
                self._send_json({"error": "Invalid report name"}, HTTPStatus.BAD_REQUEST)
                return
            rep_path = ROOT / "reports" / name
            self._send_json({"name": name, "content": safe_read(rep_path)})
            return

        if parsed.path == "/api/policy":
            qs = parse_qs(parsed.query)
            name = qs.get("name", [""])[0]
            if not name or "/" in name or ".." in name or not name.endswith(".json"):
                self._send_json({"error": "Invalid policy name"}, HTTPStatus.BAD_REQUEST)
                return
            pol_path = ROOT / "policies" / name
            self._send_json({"name": name, "content": safe_read(pol_path)})
            return

        self._send_text("Not found", HTTPStatus.NOT_FOUND)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/build":
            self._send_json(run_cmd(["make", "clean", "all"]))
            return

        if parsed.path == "/api/run":
            body = self._json_body()
            target = body.get("target", "./test")
            args = body.get("args", "")
            cmd = [target] + shlex.split(args)
            self._send_json(run_cmd(cmd))
            return

        if parsed.path == "/api/sandbox":
            body = self._json_body()
            policy = body.get("policy", "policies/restrictive.json")
            target = body.get("target", "./test")
            args = body.get("args", "")
            cmd = ["./sandbox-run", policy, target] + shlex.split(args)
            self._send_json(run_cmd(cmd))
            return

        if parsed.path == "/api/make-report":
            body = self._json_body()
            policy = body.get("policy", "policies/restrictive.json")
            target = body.get("target", "./test")
            args = body.get("args", "")
            workload_label = str(body.get("workloadLabel", "ad-hoc")).strip() or "ad-hoc"
            cmd = ["make", "report", f"POLICY={policy}", f"TARGET={target}"]
            if args.strip():
                cmd.append(f"REPORT_ARGS={args}")
            self._send_json(run_cmd(cmd, extra_env={"WORKLOAD_LABEL": workload_label}))
            return

        if parsed.path == "/api/demo-suite":
            body = self._json_body()
            workload_label = str(body.get("workloadLabel", "ad-hoc")).strip() or "ad-hoc"
            self._send_json(run_cmd(["make", "demo-suite"], extra_env={"WORKLOAD_LABEL": workload_label}))
            return

        if parsed.path == "/api/benchmark":
            body = self._json_body()
            policy = body.get("policy", "policies/restrictive.json")
            target = body.get("target", "./test")
            args = body.get("args", "")
            workload_label = str(body.get("workloadLabel", "ad-hoc")).strip() or "ad-hoc"
            iterations = str(body.get("iterations", "5")).strip() or "5"
            cmd = ["make", "benchmark", f"POLICY={policy}", f"TARGET={target}"]
            if args.strip():
                cmd.append(f"REPORT_ARGS={args}")
            self._send_json(
                run_cmd(
                    cmd,
                    extra_env={"BENCH_ITERATIONS": iterations, "WORKLOAD_LABEL": workload_label},
                )
            )
            return

        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Sandbox GUI running at http://{HOST}:{PORT}")
    print(f"Project root: {ROOT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
