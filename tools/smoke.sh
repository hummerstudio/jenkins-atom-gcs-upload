#!/usr/bin/env bash
# A real RSA key: the fake token endpoint verifies the assertion signature and the claims it carries.
set -uo pipefail
cd "$(dirname "$0")/.."
./build.sh >/dev/null || { echo "build failed" >&2; exit 1; }
. tools/smoke-lib.sh

keys="$(mktemp -d)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$keys/key.pem" 2>/dev/null || {
  echo "smoke needs openssl with RSA support" >&2; exit 1; }
openssl rsa -in "$keys/key.pem" -pubout -out "$keys/pub.pem" 2>/dev/null
pem_json=$(python3 -c "import json,sys;print(json.dumps(open('$keys/key.pem').read()))")

log="$(mktemp)"; port=$((23000 + RANDOM % 900))
start() { python3 tools/fake_gcs.py "$port" "$log" "$keys/pub.pem" "$@" & server=$!;
  for _ in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.1; done; }
stop() { kill $server 2>/dev/null; wait $server 2>/dev/null; }
start; trap 'stop' EXIT

ws="$(mktemp -d)"; mkdir -p "$ws/build/libs"
printf 'jar-bytes' >"$ws/build/libs/app-1.0.0.jar"

write_input() { # write_input <extra-json> [secret-key-json]
  cat >"$ws/input.json" <<EOF
{"bucket": "acme-artifacts", "clientEmail": "ci@acme.iam.gserviceaccount.com",
 "tokenUrl": "http://127.0.0.1:$port/token", "uploadUrl": "http://127.0.0.1:$port",
 "files": "build/libs/*.jar" $1}
EOF
  if [ -n "${2:-}" ]; then printf '{"privateKey": %s}' "$2" >"$ws/.secrets.json"; else
    printf '{"privateKey": %s}' "$pem_json" >"$ws/.secrets.json"; fi
}

write_input ', "objectPrefix": "1.0.0"'
run "$ws" >"$ws/atom.log" 2>&1 || fail "upload failed: $(cat "$ws/output.json")"
[ "$(output "$ws" uploaded)" = "1" ] || fail "uploaded: $(cat "$ws/output.json")"
[ "$(output "$ws" bytes)" = "9" ] || fail "bytes: $(cat "$ws/output.json")"

python3 - "$log" <<'PY' || fail "the assertion or the upload was wrong: $(cat "$log")"
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]).read().strip().splitlines()]
token = [l for l in lines if l["path"].startswith("/token")][-1]
assert token["signatureOk"], token.get("error")
claims = token["claims"]
assert claims["iss"] == "ci@acme.iam.gserviceaccount.com", claims
assert claims["scope"].endswith("devstorage.read_write"), claims
assert claims["aud"].startswith("http://127.0.0.1:") and claims["aud"].endswith("/token"), claims
upload = [l for l in lines if l["path"].startswith("/upload/")][-1]
assert upload["uploadType"] == "media", upload
assert upload["name"] == "1.0.0/app-1.0.0.jar", upload
assert upload["authorization"] == "Bearer ya29.fake-token", upload
assert upload["size"] == 9, upload
PY
grep -q '"claims"' "$log" || fail "the token endpoint never saw an assertion"

# without a prefix the relative path is the object name
: >"$log"; write_input ""
run "$ws" >"$ws/atom.log" 2>&1 || fail "upload without prefix failed"
python3 - "$log" <<'PY' || fail "object name: $(tail -1 "$log")"
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]).read().strip().splitlines()]
upload = [l for l in lines if l["path"].startswith("/upload/")][-1]
assert upload["name"] == "build/libs/app-1.0.0.jar", upload
PY

# a refused token exchange is a credential problem and says why
stop; start --refuse-token "Invalid JWT: audience mismatch"
write_input ""
run "$ws" >"$ws/atom.log" 2>&1 && fail "a refused token must fail the step"
grep -q "audience mismatch" "$ws/output.json" || fail "the refusal reason is missing: $(cat "$ws/output.json")"
grep -q '"errorType":1' "$ws/output.json" || fail "a 400 from the token endpoint should be USER(1)"

# a broken key never reaches the network
stop; start
write_input "" '"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"'
run "$ws" >"$ws/atom.log" 2>&1 && fail "an unparsable key must fail"
grep -q "could not sign the assertion" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"

# missing inputs
write_input ""
python3 - "$ws" <<'PY'
import json, sys
path = sys.argv[1] + "/input.json"
doc = json.load(open(path)); doc.pop("bucket"); json.dump(doc, open(path, "w"))
PY
run "$ws" >"$ws/atom.log" 2>&1 && fail "missing bucket must be refused"
grep -q "bucket is required" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"

echo "smoke ok: RS256 assertion verified, claims checked, object names, refused token, broken key, missing input"
