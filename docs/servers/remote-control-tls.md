# RemoteControl TLS, systemd и работа с подписанными релизами (0.42.8)

RemoteControl is a **host supervisor**, not an arbitrary remote shell. Its HTTPS API accepts only `host.status`, `host.start`, `host.stop`, and `host.restart`, with short-lived, scoped tokens, CIDR allowlists, auditable requests and durable idempotency receipts. It does not execute arbitrary Java arguments or shell commands.

## Подготовка сертификатов TLS (настоящие X.509, без подпроцесса OpenSSL)

Run on a trusted operator machine with a secure, **new** directory (the command refuses to overwrite existing credentials):

```bash
nl server-bridge host remote tls-init \
  --output-dir /secure/operator/remote-credentials-001 \
  --host 10.10.0.21 --host host1.example.internal --days 30
```

The command generates an Ed25519 CA, an IP/DNS-SAN server certificate (`server.pem`/`server.key`), and a separate client-authentication certificate (`client.pem`/`client.key`). Every private key is created with `0600`; the directory is `0700`. The CA is valid for the leaf lifetime plus one day. SHA-256 of the CA public key is returned for out-of-band verification. All certificates are verified against the generated CA before the command succeeds.

**Move `ca.key` offline immediately.** Never copy the CA private key or `client.key` to the game host. Copy `server.pem`, `server.key` and public `ca.pem` to a path readable by the non-root RemoteControl service account. Store `client.key` exclusively on the trusted operator machine. Never put any keys in the repository, release ZIP, web root or shared storage. Reissue credentials in a fresh directory before expiry; do not mutate an existing certificate set in place.

Initialize the server identity once and start the TLS listener with mutual TLS (copy public CA to host):

```bash
nl server-bridge host remote init --server-root /srv/minecraft/survival
nl server-bridge host remote serve --server-root /srv/minecraft/survival \
  --listen 10.10.0.21:9443 \
  --tls-cert /etc/launcher/remote/server.pem \
  --tls-key /etc/launcher/remote/server.key \
  --client-ca /etc/launcher/remote/ca.pem \
  --allow-source 10.10.0.5/32
```

The server verifies the client certificate against the CA *and* verifies its scoped bearer token. Obtain the scoped token with `remote issue --subject ... --scope ... --source ... --ttl-seconds ... --token-file ...` and keep that token file private (`0600`). The client must use `--ca-file`, `--client-cert`, `--client-key` when calling the server. Never use `--insecure`/skip-verification; those modes do not exist.

## Эксплуатация службы systemd

Use `nl server-bridge host service install --component remote --scope system --name remote-survival --server-root ... --service-user ... --tls-cert ... --tls-key ... --client-ca ... --listen ... --allow-source ... --now`. The installed service remains an unprivileged unit. A SIGTERM causes the remote HTTPS listener to stop accepting new work, allows up to **90 seconds** for existing requests and their durable command receipts to finish, and then fails visibly if that drain cannot complete. The generated unit sets `TimeoutStopSec=105s` rather than killing the listener at its previous 45-second timeout. Never automatically repeat a command with a different idempotency key after loss of acknowledgement; inspect the receipt first.

Both services now use `Type=notify` with `NotifyAccess=main` and `WatchdogSec=30s`. The Minecraft Host reports readiness only for a verified running child. **RemoteControl separately reports `READY=1` only after binding its HTTPS listener**, periodically sends `WATCHDOG=1` while serving, and sends `STOPPING=1` before journal-preserving shutdown. An absent or broken `NOTIFY_SOCKET` fails readiness when configured; an unexpected listener exit is treated as a service failure. No watchdog success implies that a Minecraft child is healthy; that remains the Host supervisor's responsibility.

## подписи релизов и границы сертификатов

`nl release sign` continues to use Ed25519 signatures and the existing independent GA gates. A trusted signing/verification key must be outside the bundle **both by its path and by its resolved real path**. Symlink aliases into the release tree are rejected. A 64-byte Ed25519 private key with a public component inconsistent with its private seed is refused. These improvements do not replace Authenticode notarization/platform signatures or provide approval for an unverified Minecraft/ServerBridge matrix.
