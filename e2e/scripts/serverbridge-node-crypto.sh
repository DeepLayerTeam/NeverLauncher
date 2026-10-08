#!/usr/bin/env bash
# Общий рабочий-like Ed25519 вспомогательный модуль для ServerBridge E2E. Исходник этот файл.
# Требует: openssl, Python3, curl, sha256sum.

serverbridge_node_public() {
  local key="$1"
  openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | python3 -c 'import base64,sys; d=sys.stdin.buffer.read();
if len(d) < 32: raise SystemExit("invalid Ed25519 public key")
print(base64.urlsafe_b64encode(d[-32:]).decode().rstrip("="))'
}

serverbridge_node_generate() {
  local key="$1" identity_file="$2" parent private_der public_der
  parent="$(dirname "$identity_file")"
  mkdir -p "$(dirname "$key")" "$parent"
  chmod 0700 "$(dirname "$key")" "$parent" 2>/dev/null || true
  openssl genpkey -algorithm Ed25519 -out "$key" >/dev/null 2>&1
  chmod 0600 "$key"
  private_der="$(mktemp)"
  public_der="$(mktemp)"
  trap 'rm -f "$private_der" "$public_der"' RETURN
  openssl pkcs8 -topk8 -nocrypt -in "$key" -outform DER -out "$private_der" >/dev/null 2>&1
  openssl pkey -in "$key" -pubout -outform DER -out "$public_der" >/dev/null 2>&1
  python3 - "$private_der" "$public_der" "$identity_file" <<'PY'
import base64, hashlib, pathlib, sys
private_der = pathlib.Path(sys.argv[1]).read_bytes()
public_der = pathlib.Path(sys.argv[2]).read_bytes()
if len(public_der) < 32:
    raise SystemExit("invalid Ed25519 X.509 public key")
raw = public_der[-32:]
b64 = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
out = pathlib.Path(sys.argv[3])
out.write_text(
    "formatVersion=1\n"
    "keyAlgorithm=ed25519\n"
    f"publicKey={b64(raw)}\n"
    f"keyFingerprint={hashlib.sha256(raw).hexdigest()}\n"
    f"publicKeyX509={b64(public_der)}\n"
    f"privateKeyPkcs8={b64(private_der)}\n",
    encoding="ascii",
)
out.chmod(0o600)
PY
  rm -f "$private_der" "$public_der"
  trap - RETURN
}

serverbridge_node_sign() {
  local key="$1" canonical="$2" canonical_file signature_file signature
  canonical_file="$(mktemp)" || return 1
  signature_file="$(mktemp)" || { rm -f "$canonical_file"; return 1; }

  if ! printf '%s' "$canonical" > "$canonical_file"; then
    rm -f "$canonical_file" "$signature_file"
    return 1
  fi
  # Ed25519 является одноразовый algorithm в OpenSSL. pkeyutl должен получать seekable
  # input файл; piping канонический полезная нагрузка через стандартный ввод может завершаться ошибкой с
  # "unable к determine файл размер для oneshot операция" и yield 0 байты.
  if ! openssl pkeyutl -sign -rawin -inkey "$key" -in "$canonical_file" -out "$signature_file" >/dev/null 2>&1; then
    rm -f "$canonical_file" "$signature_file"
    return 1
  fi
  if ! signature="$(python3 - "$signature_file" <<'PY'
import base64, pathlib, sys
sig = pathlib.Path(sys.argv[1]).read_bytes()
if len(sig) != 64:
    raise SystemExit(f"invalid Ed25519 signature length: {len(sig)}")
print(base64.urlsafe_b64encode(sig).decode().rstrip("="))
PY
  )"; then
    rm -f "$canonical_file" "$signature_file"
    return 1
  fi
  rm -f "$canonical_file" "$signature_file"
  printf '%s\n' "$signature"
}

serverbridge_node_signed_request() {
  local key="$1" node_id="$2" method="$3" url="$4" body="$5" out="$6"
  local timestamp nonce target body_hash canonical signature
  timestamp="$(date +%s)"
  nonce="$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("="))')"
  target="$(python3 - "$url" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
t = u.path or "/"
if u.query:
    t += "?" + u.query
print(t)
PY
)"
  body_hash="$(printf '%s' "$body" | sha256sum | awk '{print $1}')"
  canonical="$(printf 'NeverLauncher-ServerBridge-Node-v1\n%s\n%s\n%s\n%s\n%s\n%s' "$node_id" "${method^^}" "$target" "$timestamp" "$nonce" "$body_hash")"
  signature="$(serverbridge_node_sign "$key" "$canonical")"

  local args=(-sS -o "$out" -w '%{http_code}' -X "${method^^}"
    -H "X-NeverLauncher-Node-Id: $node_id"
    -H "X-NeverLauncher-Node-Key-Fingerprint: $(serverbridge_node_public "$key" | python3 -c 'import base64,hashlib,sys; s=sys.stdin.read().strip(); d=base64.urlsafe_b64decode(s+"="*((4-len(s)%4)%4)); print(hashlib.sha256(d).hexdigest())')"
    -H "X-NeverLauncher-Node-Timestamp: $timestamp"
    -H "X-NeverLauncher-Node-Nonce: $nonce"
    -H "X-NeverLauncher-Node-Signature: $signature")
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' --data-binary "$body")
  fi
  curl "${args[@]}" "$url"
}
