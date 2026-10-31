#!/usr/bin/env python3
"""A Google-shaped token endpoint plus an upload endpoint that verifies the assertion.

    fake_gcs.py <port> <log> <public-key.pem> [--refuse-token 'reason'] [--upload-status 200]
"""
import base64
import http.server
import json
import subprocess
import sys
import tempfile
import urllib.parse

port, log_path, public_key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
refuse_token = ""
upload_status = 200
args = sys.argv[4:]
while args:
    flag = args.pop(0)
    if flag == "--refuse-token":
        refuse_token = args.pop(0)
    elif flag == "--upload-status":
        upload_status = int(args.pop(0))


def verify_assertion(assertion):
    """Check the RS256 signature with openssl and return the claims, or raise with a reason."""
    head, claims, signature = assertion.split(".")
    signing_input = f"{head}.{claims}".encode("ascii")
    signature_bytes = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    with tempfile.NamedTemporaryFile(delete=False) as data:
        data.write(signing_input)
        data_path = data.name
    with tempfile.NamedTemporaryFile(delete=False) as sig:
        sig.write(signature_bytes)
        sig_path = sig.name
    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", public_key,
                             "-signature", sig_path, data_path], capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError("bad signature: " + (result.stderr or result.stdout).strip())
    return json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))


class Handler(http.server.BaseHTTPRequestHandler):
    def _record(self, entry):
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(json.dumps(entry) + "\n")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.path.startswith("/token"):
            form = urllib.parse.parse_qs(raw.decode("utf-8"))
            assertion = form.get("assertion", [""])[0]
            entry = {"path": self.path, "grant": form.get("grant_type", [""])[0]}
            if refuse_token:
                entry["refused"] = refuse_token
                self._record(entry)
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid_grant", "error_description": refuse_token}).encode())
                return
            try:
                claims = verify_assertion(assertion)
                entry["claims"] = claims
                entry["signatureOk"] = True
            except Exception as error:
                entry["signatureOk"] = False
                entry["error"] = str(error)
                self._record(entry)
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid_grant", "error_description": str(error)}).encode())
                return
            self._record(entry)
            body = json.dumps({"access_token": "ya29.fake-token", "expires_in": 3599}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/upload/storage/v1/"):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            self._record({
                "path": self.path,
                "name": query.get("name", [""])[0],
                "uploadType": query.get("uploadType", [""])[0],
                "authorization": self.headers.get("Authorization"),
                "contentType": self.headers.get("Content-Type"),
                "size": len(raw),
            })
            if upload_status != 200:
                self.send_response(upload_status)
                self.end_headers()
                self.wfile.write(b'{"error":{"code":403,"message":"forbidden"}}')
                return
            body = json.dumps({"name": query.get("name", [""])[0],
                               "selfLink": "https://storage.googleapis.com/storage/v1/b/b/o/" + query.get("name", [""])[0]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
