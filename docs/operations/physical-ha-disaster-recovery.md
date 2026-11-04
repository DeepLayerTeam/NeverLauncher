# NeverLauncher 0.52.10 — эксплуатация физического HA и аварийного восстановления

**Executable production paths, not an assertion of completed acceptance.** These commands are deliberately destructive. Use an isolated, independently operated hardware lab with no live customers. The 0.52.10 CI tests are local regressions; physical host shutdown, routed network isolation, PostgreSQL/Redis/S3 promotion, downstream notifications and recovered Minecraft gameplay must be observed on the target infrastructure before any physical acceptance receipt can be considered valid.

## Разделение ответственности

The observer is a Linux host **outside** the HA failure domains. Two or more distinct physical API/worker hosts run the real `multi_host_0512.py` deployment, immutable images, TLS load balancer and shared PostgreSQL/Redis/S3. A separate Redfish BMC management network must survive loss of the application host. The target must be a lab machine whose **actual Redfish SerialNumber** matches `--expected-serial`. BMC HTTPS uses a real trusted CA file; no `-k`, silent redirects, password-in-URL or raw credentials in receipt files. Use per-host restricted Redfish API tokens in private 0600 files. The BMC account must be able to issue `ForceOff` and `On` on the approved system. Confirm those `ResetType` operations are supported by the specific BMC before testing.

The observer needs pinned SSH host keys and limited sudo rights on only the approved HA nodes and on the dedicated router. Pre-create a directory mode 0700 owned by the observer. Every physical fault writes an exclusive, fsynced `--state` journal **before** the remote mutation. Incomplete or uncertain faults keep the journal and must be recovered through `heal` before another drill. Do not delete a journal just to bypass the check. All reports are mode 0600 and written exactly once.

### Реальные уведомления зависимых систем

The bundled `scripts/operations/alert_receiver_05210.py` is a functioning Alertmanager webhook receiver: `POST /webhook` authenticates with a dedicated Bearer token, validates a real firing event and SHA-compatible fingerprint, and atomically fsyncs its receipt into `latest.json`; `GET /events/latest` requires a **different** reader token. It binds to **127.0.0.1 only**. Place a separately managed HTTPS reverse proxy with a verified certificate at an independent notification host; forward those two paths to localhost. Both token files must be non-symlink private 0600 regular files; the receiver directory must be 0700 and owned by its process. Example receiver start:

```sh
python3 scripts/operations/alert_receiver_05210.py \
  --directory /srv/neverlauncher-alert-receipts --port 18871 \
  --expected-alert NeverLauncherHostIngressDown \
  --webhook-token-file /etc/launcher/alerts-webhook.token \
  --reader-token-file /etc/launcher/alerts-observer.token
```

Configure the existing real Alertmanager routing to deliver the required alert to `https://notifications.example.net/webhook` with `http_config.authorization.credentials_file` containing the webhook Bearer token (not the reader token). Protect the HTTPS endpoint and do not expose the loopback receiver directly. The physical runner independently polls **both** Alertmanager `/api/v2/alerts` and the external notification host's `/events/latest`, matching the alert name, fingerprint and timestamps **after** the fault began. Existing alert state without a downstream delivery receipt is a BLOCKED result, not PASS. A healthy cluster without an actual alert is also BLOCKED. Choose `--alert-name` from the deployed Prometheus rules for the targeted failure (for example `NeverLauncherHostIngressDown`).

## 1. Потеря питания физического сервера: BMC ForceOff и восстановление

Verify the observer can still reach every server over its own management network and the public HTTPS ingress. On an independent observer with private files in `/secure/physical-05210`:

```sh
python3 scripts/operations/physical_ha_dr_05210.py host \
  --node a=ops@node-a.example.net --node b=ops@node-b.example.net \
  --victim a --project launcher \
  --directory /opt/launcher/deploy/production \
  --edge-url https://launcher.example.net/ready \
  --redfish-url https://bmc-a.example.net/redfish/v1/Systems/1 \
  --expected-serial REAL-BMC-SERIAL-A \
  --bmc-ca /secure/physical-05210/bmc-ca.pem \
  --bmc-token-file /secure/physical-05210/bmc.token \
  --alertmanager-url https://alerts.example.net \
  --delivery-url https://notifications.example.net/events/latest \
  --delivery-token-file /secure/physical-05210/alerts-reader.token \
  --alert-name NeverLauncherHostIngressDown \
  --state /secure/physical-05210/active.state.json \
  --report /secure/physical-05210/power-a.report.json \
  --allow-disruption I-ACCEPT-PHYSICAL-OUTAGE
```

This performs a real Redfish power transition, observes BMC `Off` and the loss of SSH to the **specific** host, verifies the surviving independently identified nodes and repeated public HTTPS ingress, verifies external alert delivery, requests BMC `On` even after a failed observation, then checks full cluster recovery. Successful `systemctl stop` or `docker stop` alone does not satisfy this scenario. A BMC recovery failure or missing post-recovery baseline leaves the journal in place.

## 2. Разделение сети в *маршрутизируемой* физической сети приложения

Install `deploy/production/physical-partition-05210.nft` **only** on a dedicated L3 Linux router between the targeted real node and other nodes/dependencies. The `inet launcher_partition_05210` table has an isolated forwarding chain and an expiring dynamic IPv4 set; no host is blocked until a particular private address is added. Verify both source and destination forwarding rules and the kernel timeout set. Ensure the out-of-band management/BMC network and the observer are **not** routed through this firewall. On a shared L2 segment, this method does not partition switch-local peer traffic; the live peer TCP probes will refuse PASS. It does not claim to test arbitrary physical fiber/cable failure.

```sh
# Запустите однократно на выделенном маршрутизаторе после оценки точных последствий:
sudo nft -f /opt/launcher/deploy/production/physical-partition-05210.nft
# Затем на независимом наблюдателе:
python3 scripts/operations/physical_ha_dr_05210.py partition \
  --node a=ops@node-a.example.net --node b=ops@node-b.example.net \
  --victim a --victim-ip 10.14.0.11 --victim-port 443 \
  --router ops@router.example.net --ttl 190 --timeout 120 \
  --project launcher --directory /opt/launcher/deploy/production \
  --edge-url https://launcher.example.net/ready \
  --redfish-url https://bmc-a.example.net/redfish/v1/Systems/1 \
  --expected-serial REAL-BMC-SERIAL-A \
  --bmc-ca /secure/physical-05210/bmc-ca.pem \
  --bmc-token-file /secure/physical-05210/bmc.token \
  --alertmanager-url https://alerts.example.net \
  --delivery-url https://notifications.example.net/events/latest \
  --delivery-token-file /secure/physical-05210/alerts-reader.token \
  --alert-name NeverLauncherHostIngressDown \
  --state /secure/physical-05210/active.state.json \
  --report /secure/physical-05210/partition-a.report.json \
  --allow-disruption I-ACCEPT-PHYSICAL-OUTAGE
```

The verifier requires TCP from every surviving node to the victim's real application port **before** the fault, loss of that TCP while the BMC still says `On` and **management SSH remains reachable**, healthy surviving services and ingress, external alert delivery, and recovery of peer TCP plus all cluster processes. The kernel timeout removes a residual set entry if the observer is terminated. The tool also removes the entry explicitly on exit. A TTL shorter than the required observation window is rejected. A disappearance of management SSH by itself is **not** accepted as physical network partition evidence.

## 3. Переключение зависимостей PostgreSQL/Redis/S3 при отказе

The existing `dependency_ha_0513.py` is invoked directly by the 0.52.10 controller. On PostgreSQL/Redis it now refuses a replica stop and demands that the **actual current primary** be disrupted and a different active primary be observed. The approved SSH target is verified to own the configured backend IPv4 on its real network interface, even if SSH management uses an unrelated IP. For S3, signed S3 PUT/readback across remaining gateways is performed through the production health verifier. The controller pre-schedules a remote transient `systemd-run` unit to restart the disrupted service even if the observer process is killed, writes its recovery journal, and checks both failover and restored redundancy. Requires real Patroni/Redis/S3 clusters and restricted root permissions, not a Compose replacement.

```sh
python3 scripts/operations/physical_ha_dr_05210.py dependency \
  --service patroni --backend-server pg-primary-a --target ops@pg-node-a.example.net \
  --ha-env-file /etc/launcher/ha-0513.env \
  --ha-socket /run/haproxy/launcher-ha.sock \
  --edge-url https://launcher.example.net/ready \
  --alertmanager-url https://alerts.example.net \
  --delivery-url https://notifications.example.net/events/latest \
  --delivery-token-file /secure/physical-05210/alerts-reader.token \
  --alert-name NeverLauncherBackendNotReady \
  --state /secure/physical-05210/active.state.json \
  --report /secure/physical-05210/postgres-failover.report.json \
  --allow-disruption I-ACCEPT-PHYSICAL-OUTAGE
```

Run with `--service redis-server` for Redis and `--service minio` for an S3 gateway, with the real backend identity and corresponding SSH target. The backend name must exist in the configured HAProxy inventory. If the service or quorum remains unhealthy, the dependency recovery journal is retained; use verified `heal --heal-mode dependency` after repairing the cluster. A single provider's successful health check is not a full replicated-storage RPO statement. Reconcile acknowledged PostgreSQL transactions and S3/world objects separately using the existing cohort/DR tools.

## 4. Восстановление остановленного мира Minecraft с побайтовой проверкой на новом игровом узле

First capture a **confirmed-stopped** production world backup with the existing ServerBridge/DR tooling. Restore PostgreSQL WAL, S3, protected identities, permissions and extension state with `cross_host_recovery_0519.py prepare`, `replay-postgres`, `admit`; separately validate incident-to-ready RTO, sampled audit RPO and source cutover. The **old physical Minecraft server must still be BMC `Off`** to block dual world writers. Run this `world` mode on the recovered game host, with a *fresh non-existent destination*, a private RCON password file, verified server startup/stop scripts (absolute executable paths, not shell snippets) and an actual licensed player who will connect during the probe:

```sh
python3 scripts/operations/physical_ha_dr_05210.py world \
  --world-backup /srv/recovery/worlds/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --world-destination /srv/recovered-game/instance-1 \
  --game-start /usr/local/sbin/start-recovered-vanilla \
  --game-stop /usr/local/sbin/stop-recovered-vanilla \
  --game-config /secure/physical-05210/recovered-game.json \
  --rcon-password-file /secure/physical-05210/rcon.token \
  --expected-player VerifiedPlayer \
  --marker-xyz '0 64 0' --marker-block minecraft:diamond_block \
  --redfish-url https://old-game-bmc.example.net/redfish/v1/Systems/1 \
  --expected-serial OLD-GAME-BMC-SERIAL \
  --bmc-ca /secure/physical-05210/bmc-ca.pem \
  --bmc-token-file /secure/physical-05210/old-game-bmc.token \
  --source-fenced --allow-disruption I-ACCEPT-PHYSICAL-OUTAGE \
  --report /secure/physical-05210/world-restore.report.json
```

The private JSON game config contains `serverDir` (exactly the fresh restored directory), `minecraftVersion` (`1.21.1` for this specific Vanilla probe), `minecraftPort` and `rconPort`. The scripts must manage the **real restored JVM**; startup must return once the game process is launched, not once it is terminated. The target world must contain the pre-backup block marker; only the actually observed RCON `execute if block ... run say ...` response with the exact marker is accepted. The verifier copies and rehashes every world file with `dr_03512.restore_world_backup`, checks live Minecraft status, player presence, advancing game ticks and marker content, then invokes the real server stop action. A successful copy or a Minecraft menu screen does not pass the game recovery stage. **This tests one recovered world and one real player; it does not prove all acknowledged world writes survived.**

## Восстановление после прерванного испытания сбоя

```sh
python3 scripts/operations/physical_ha_dr_05210.py heal \
  --heal-mode host --victim a \
  --redfish-url https://bmc-a.example.net/redfish/v1/Systems/1 \
  --expected-serial REAL-BMC-SERIAL-A \
  --bmc-ca /secure/physical-05210/bmc-ca.pem \
  --bmc-token-file /secure/physical-05210/bmc.token \
  --state /secure/physical-05210/active.state.json
```

For router isolation, pass `--heal-mode partition`, `--router`, `--victim-ip`, `--victim-port` and the original two `--node label=target` arguments instead and keep the real BMC options where applicable. For a disrupted dependency, pass `--heal-mode dependency --target ... --backend-server ... --service ... --ha-env-file ... --ha-socket ... --edge-url ...`. `heal` only clears the journal after actual independent physical/service recovery; it does **not** issue a GA certificate.

## CI и границы версии 0.53.0

The new `.github/workflows/physical-ha-dr-05210.yml` runs local negative tests without hardware on ordinary CI. Its destructive job is available only via explicit `workflow_dispatch`, a protected `physical-ha-lab` environment and a separately labeled self-hosted hardware runner; credentials are provided as environment secrets, not committed to the repository. The live runner exits nonzero on missing equipment, missing alerts, failed quorum, missing marker/player or interrupted restore; it never fabricates receipt files to make CI green.

0.52.10 supplies **working physical control, safety, live verification and world restore code**, but the current source archive has no actual BMC, dedicated router, physical dependency quorum, real game host, signed final installers or independent external incident receipts. These must be executed before declaring that 0.52.10 has completed a physical HA GA acceptance. The separate 0.53.0 full matrix/final-byte independent certification remains **BLOCKED**. Source receipt JSON is only an observation and must later be independently signed and linked to final release hashes through the existing acceptance mechanisms.
