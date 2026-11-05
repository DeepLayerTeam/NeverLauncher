#!/usr/bin/env python3
"""Автономная выдача/отзыв делегированного сертификата выпуска на закреплённой подписанной политике.

Корневой якорь передаётся явно, а не извлекается из политики. Эпоха увеличивается при каждом
изменении. Используется производственный код подписания доверия; действующие правила проверки
компонентов и отзыва продолжают применяться.
"""

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("release_root_signing_0496", BASE / "sign-trust-policy.py")
root_signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(root_signing)
ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")


class CertificateError(Exception):
    pass


def current_policy(path, expected_sha256, root_public):
    if not SHA256.fullmatch(expected_sha256) or path.is_symlink() or not path.is_file():
        raise CertificateError("Требуется: «signed source and pinned SHA-256»")
    raw = path.read_bytes()
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise CertificateError("signed policy changed since review")
    env = json.loads(raw, object_pairs_hook=root_signing._no_duplicate_keys)
    if env.get("schemaVersion") != "1.0":
        raise CertificateError("Неожиданное значение: «signed trust envelope»")
    payload = base64.b64decode(env['payload'], validate=True)
    root = Ed25519PublicKey.from_public_bytes(bytes.fromhex(root_public))
    root.verify(bytes.fromhex(env['rootSignature']), root_signing.PREFIX + payload)
    with tempfile.TemporaryDirectory(prefix='trust-cert-validate-') as tmp:
        path2 = Path(tmp) / 'policy.json'
        path2.write_bytes(payload)
        root_signing._read_policy(path2)
    return json.loads(payload, object_pairs_hook=root_signing._no_duplicate_keys)


def rotate(*, signed_policy, expected_sha256, output, root_public, root_seed, operation,
           key_id, private_key_output=None):
    signed_policy, output = Path(signed_policy), Path(output)
    if not ID.fullmatch(key_id):
        raise CertificateError("Некорректное значение: «delegated key ID»")
    existing = current_policy(signed_policy, expected_sha256, root_public)
    if existing['epoch'] >= 2**64 - 1:
        raise CertificateError("trust epoch overflow")
    existing['epoch'] += 1
    ids = [entry['id'] for entry in existing['keys']]
    private = None
    if operation == 'issue':
        if key_id in ids or private_key_output is None:
            raise CertificateError("Обнаружен дубликат: «key ID or no private key destination»")
        private_key_output = Path(private_key_output)
        if private_key_output.exists() or private_key_output.is_symlink() or private_key_output == output:
            raise CertificateError("Для «private seed destination» требуется: «new»")
        private = Ed25519PrivateKey.generate()
        pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        existing['keys'].append({'id': key_id, 'role': 'component', 'status': 'active', 'publicKey': pub,
                                 'notBefore': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')})
    elif operation == 'revoke':
        if private_key_output is not None or key_id not in ids:
            raise CertificateError("Не удалось отозвать «unknown key or write a private seed»")
        key = next(k for k in existing['keys'] if k['id'] == key_id)
        if key['status'] != 'active':
            raise CertificateError("delegation already revoked")
        key['status'] = 'revoked'
    else:
        raise CertificateError("Неизвестное значение: «certificate operation»")
    # Новая эпоха выдачи и отзыва подписывается существующим закреплённым
    # автономным корнем; новый закрытый seed никогда не помещается в JSON
    # политики.
    staged_seed = None
    try:
        if private is not None:
            seed_bytes = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            fd = os.open(private_key_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            staged_seed = private_key_output
            with os.fdopen(fd, 'wb') as writer:
                os.fchmod(writer.fileno(), 0o600)
                writer.write(seed_bytes.hex().encode() + b'\n')
                writer.flush()
                os.fsync(writer.fileno())
        with tempfile.TemporaryDirectory(prefix='trust-cert-') as tmp:
            tmp_policy = Path(tmp) / 'policy.json'
            tmp_policy.write_text(json.dumps(existing, sort_keys=True, separators=(',', ':')) + '\n')
            root_signing.sign_policy(tmp_policy, output, root_seed, root_public)
        return {'operation': operation, 'keyId': key_id, 'epoch': existing['epoch'],
                'signedPolicySha256': hashlib.sha256(output.read_bytes()).hexdigest()}
    except Exception:
        # Если подпись корневым ключом не удалась, никогда не оставляйте на диске
        # непригодный закрытый seed.
        if staged_seed is not None:
            staged_seed.unlink(missing_ok=True)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('issue', 'revoke'))
    p.add_argument('--signed-policy', type=Path, required=True)
    p.add_argument('--expected-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--root-public', required=True)
    p.add_argument('--key-id', required=True)
    p.add_argument('--private-key-output', type=Path)
    a = p.parse_args()
    root_seed = os.environ.get('LAUNCHER_TRUST_ROOT_ED25519_SEED', '')
    if not root_seed:
        p.error('offline root signing seed is required')
    try:
        print(json.dumps(rotate(signed_policy=a.signed_policy, expected_sha256=a.expected_sha256,
                                output=a.output, root_public=a.root_public, root_seed=root_seed,
                                operation=a.operation, key_id=a.key_id,
                                private_key_output=a.private_key_output), sort_keys=True))
    except Exception as err:
        p.exit(2, f'certificate operation rejected: {err}\n')


if __name__ == '__main__':
    main()
