# Control Domains & RBAC — Launcher 0.28.1

This release changes **live authorization of ServerBridge v3 game commands**; it does not install a Host RemoteControl agent or provide Backend restart (those are later roadmap milestones).

| Command | Required project permission | Domain |
| --- | --- | --- |
| `message.broadcast` | `gameserver:broadcast` | Game server |
| `player.kick`, `ban.*`, `whitelist.*` | `gameserver:moderate` | Game server |
| `server.save` | `gameserver:save` | Game server |
| `server.maintenance`, `server.drain` | `gameserver:traffic` | Game server |
| `server.shutdown` | `gameserver:shutdown` | Game server |
| `server.console` (allowlisted Minecraft commands only) | `gameserver:console` | Game server |

The control endpoint rejects anything else (including `host.exec`, `backend.restart`, `server.shell`). No general shell argument or executable path is accepted. `server.console` does **not** execute host shell commands, and remains restricted by the existing Minecraft command allowlist.

`backend:control`, `host:process`, and `host:exec` are distinct *global-only* RBAC actions, not project actions. They grant **no operation in ServerBridge** in this release and are not inherited from game permissions. The local Host CLI runs under the OS user's authority; this does not imply that a network RemoteControl user can execute Host operations.

## Authorization flow

1. Verify the real authenticated user and session (not the untrusted role list copied into a token). Write requests require fresh MFA within five minutes and pass risk checks.
2. Resolve the server and its real project. A caller must be able to read that project; cross-project node IDs are hidden.
3. Decode and validate the command with the existing ServerBridge v3 type and payload allowlist.
4. Match the exact command to a concrete permission in the live role repository. Deny and audit any missing permission *before the command is placed in the journal*.
5. Persist with the existing idempotency key and runtime identity. The node's signed poll/ACK flow remains unchanged.
6. On command GET and overview, re-authorize against the current role; do not return command payload/results to viewers or users whose privileges have been revoked.

## Upgrade / deployment

- Apply the new `0077_control_domains_rbac_0281.sql` migration as part of the existing schema migration runner before starting new API instances. The migration adds game-only privileges to the canonical `admin`/`operator` roles **if they still have legacy `serverbridge:control`**. An operator's old ability to request shutdown/console is intentionally not migrated; grant these separately after review.
- **Custom roles are fail-closed**: their legacy `serverbridge:control`/`serverbridge:console` strings grant none of the new command permissions. Administrators must explicitly assign each required `gameserver:*` right. Old strings can be removed after migration.
- Existing pending/leased commands created on 0.28.0 may remain in the journal; check their effects and runtime before deploying a mixed-version cluster. Drain outstanding commands before a rolling upgrade when restricting existing operators. Later HA journal changes are covered by 0.28.5, not this release.
- Mixed API versions must not serve mutation routes: **all** serving API instances should run 0.28.1 for consistent enforcement. The Game ServerBridge v3 wire protocol is unchanged.

## Verification

- `cd services/api && GOPROXY=off go test ./internal/authorization ./internal/dbmigrate`
- `cd apps/admin && npm test`
- With dependencies installed, run the full HTTP API suite, `npm run build`, migrations against a disposable PostgreSQL instance and a real ServerBridge v3 command lifecycle before treating the release as verified for production deployment.
