#!/usr/bin/env python3
"""Drive scripts/ci-artifact.sh against a fake Gitea artifact API."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci-artifact.sh"


def _md5_name(name: str) -> str:
    return hashlib.md5(name.encode(), usedforsecurity=False).hexdigest()


class _FakeGitea(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def _check_auth(self) -> bool:
        expected = f"Bearer {self.server.token}"
        if self.headers.get("Authorization") != expected:
            self.send_error(401, "Bad authorization header")
            return False
        return True

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _json(self, status: int, payload: dict) -> None:
        blob = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def _public_url(self, path: str, query: str = "") -> str:
        prefix = self.server.public_origin.rstrip("/")
        if query:
            return f"{prefix}{path}?{query}"
        return f"{prefix}{path}"

    def _parse_artifact_path(self):
        parsed = urllib.parse.urlparse(self.path)
        match = re.match(
            r"^/api/actions_pipeline/_apis/pipelines/workflows/([^/]+)/artifacts(?:/(.*))?$",
            parsed.path,
        )
        if not match:
            return None
        return match.group(1), match.group(2) or "", urllib.parse.parse_qs(parsed.query)

    def do_POST(self):
        if not self._check_auth():
            return
        parsed = self._parse_artifact_path()
        if parsed is None or parsed[1]:
            self.send_error(404)
            return
        run, _rest, _query = parsed
        if run != self.server.run_id:
            self.send_error(400, "run id mismatch")
            return
        req = json.loads(self._read_body() or b"{}")
        name = req.get("Name") or req.get("name")
        if not name:
            self.send_error(400, "missing Name")
            return
        artifact_hash = _md5_name(name)
        retention = req.get("RetentionDays") or req.get("retentionDays")
        query = f"retentionDays={retention}" if retention else ""
        self.server.pending[name] = {"files": {}, "confirmed": False, "ids": {}}
        self._json(
            200,
            {
                "fileContainerResourceUrl": self._public_url(
                    f"/api/actions_pipeline/_apis/pipelines/workflows/{run}/artifacts/{artifact_hash}/upload",
                    query,
                )
            },
        )

    def do_PUT(self):
        if not self._check_auth():
            return
        parsed = self._parse_artifact_path()
        if parsed is None:
            self.send_error(404)
            return
        run, rest, query = parsed
        if run != self.server.run_id or not rest.endswith("/upload"):
            self.send_error(404)
            return
        item_path = (query.get("itemPath") or [""])[0]
        if "/" not in item_path:
            self.send_error(400, "itemPath")
            return
        name, rel = item_path.split("/", 1)
        if _md5_name(name) != rest.split("/")[0]:
            self.send_error(400, "Invalid artifact hash")
            return
        body = self._read_body()
        expected_md5 = self.headers.get("x-actions-results-md5")
        digest = hashlib.md5(body, usedforsecurity=False).digest()
        got = base64.b64encode(digest).decode("ascii")
        if expected_md5 != got:
            self.send_error(400, "md5 mismatch")
            return
        range_hdr = self.headers.get("Content-Range") or ""
        match = re.match(r"bytes (\d+)-(\d+)/(\d+)$", range_hdr)
        if not match:
            self.send_error(400, "Content-Range")
            return
        start, end, total = (int(value) for value in match.groups())
        store = self.server.pending.setdefault(name, {"files": {}, "confirmed": False, "ids": {}})
        buf = store["files"].setdefault(rel, bytearray(total))
        if len(buf) != total:
            buf = bytearray(total)
            store["files"][rel] = buf
        buf[start : end + 1] = body
        if rel not in store["ids"]:
            self.server.next_id += 1
            store["ids"][rel] = self.server.next_id
            self.server.blobs[store["ids"][rel]] = (name, rel)
        self._json(200, {"message": "success"})

    def do_PATCH(self):
        if not self._check_auth():
            return
        parsed = self._parse_artifact_path()
        if parsed is None or parsed[1]:
            self.send_error(404)
            return
        _run, _rest, query = parsed
        name = (query.get("artifactName") or [""])[0]
        if name not in self.server.pending:
            self.send_error(400, "artifact name is empty")
            return
        self.server.pending[name]["confirmed"] = True
        self._json(200, {"message": "success"})

    def do_GET(self):
        if not self._check_auth():
            return
        parsed = self._parse_artifact_path()
        if parsed is None:
            self.send_error(404)
            return
        run, rest, query = parsed
        if not rest:
            items = []
            for name, meta in self.server.pending.items():
                if not meta["confirmed"]:
                    continue
                items.append(
                    {
                        "name": name,
                        "fileContainerResourceUrl": self._public_url(
                            f"/api/actions_pipeline/_apis/pipelines/workflows/{run}/artifacts/{_md5_name(name)}/download_url"
                        ),
                    }
                )
            if not items:
                self.send_error(404)
                return
            self._json(200, {"count": len(items), "value": items})
            return
        if rest.endswith("/download_url"):
            name = (query.get("itemPath") or [""])[0]
            meta = self.server.pending.get(name)
            if not meta or not meta["confirmed"]:
                self.send_error(404)
                return
            values = []
            for rel, file_id in meta["ids"].items():
                values.append(
                    {
                        "path": f"{name}/{rel}",
                        "itemType": "file",
                        "contentLocation": self._public_url(
                            f"/api/actions_pipeline/_apis/pipelines/workflows/{run}/artifacts/{file_id}/download"
                        ),
                    }
                )
            self._json(200, {"value": values})
            return
        if rest.endswith("/download"):
            file_id = int(rest.split("/")[0])
            pair = self.server.blobs.get(file_id)
            if not pair:
                self.send_error(404)
                return
            name, rel = pair
            blob = bytes(self.server.pending[name]["files"][rel])
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
            return
        self.send_error(404)


class _Server:
    def __init__(self, public_origin=None):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _FakeGitea)
        self.httpd.token = "test-token"
        self.httpd.run_id = "42"
        self.httpd.pending = {}
        self.httpd.blobs = {}
        self.httpd.next_id = 100
        host, port = self.httpd.server_address
        self.origin = f"http://{host}:{port}"
        self.httpd.public_origin = public_origin or self.origin
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def env(self) -> dict[str, str]:
        return {
            "ACTIONS_RUNTIME_URL": self.origin + "/api/actions_pipeline/",
            "ACTIONS_RUNTIME_TOKEN": self.httpd.token,
            "GITHUB_RUN_ID": self.httpd.run_id,
            "PATH": os.environ.get("PATH", ""),
        }


class CiArtifactTests(unittest.TestCase):
    def setUp(self):
        self.server = _Server()
        self.addCleanup(self.server.close)

    def _run(self, args, env):
        return subprocess.run(
            ["sh", str(SCRIPT), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(ROOT),
        )

    def test_cli_upload_download_roundtrip(self):
        payload = bytes((i * 31) % 256 for i in range(64 * 1024 + 17))
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ci-env.tar.gz"
            dest = Path(tmp) / "restored.tar.gz"
            src.write_bytes(payload)
            env = os.environ.copy()
            env.update(self.server.env())
            upload = self._run(["upload", "ci-env", str(src)], env)
            self.assertEqual(upload.returncode, 0, upload.stderr + upload.stdout)
            download = self._run(["download", "ci-env", str(dest)], env)
            self.assertEqual(download.returncode, 0, download.stderr + download.stdout)
            self.assertEqual(dest.read_bytes(), payload)

    def test_rebases_root_url_onto_runtime_origin(self):
        self.server.close()
        self.server = _Server(public_origin="http://gitea.example")
        self.addCleanup(self.server.close)
        payload = b"rebased-artifact-bytes"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ci-env.tar.gz"
            dest = Path(tmp) / "out.tar.gz"
            src.write_bytes(payload)
            env = os.environ.copy()
            env.update(self.server.env())
            upload = self._run(["upload", "ci-env", str(src)], env)
            self.assertEqual(upload.returncode, 0, upload.stderr + upload.stdout)
            download = self._run(["download", "ci-env", str(dest)], env)
            self.assertEqual(download.returncode, 0, download.stderr + download.stdout)
            self.assertEqual(dest.read_bytes(), payload)

    def test_download_missing_artifact_fails(self):
        env = os.environ.copy()
        env.update(self.server.env())
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "missing.tar.gz"
            download = self._run(["download", "ci-env", str(dest)], env)
            self.assertNotEqual(download.returncode, 0)


if __name__ == "__main__":
    unittest.main()
