# Discord, local discovery and Sentry (0.42.9)

The integrations use live network/IPC transports. They are **optional** and must not gate Minecraft authentication or launch. A test double in CI proves the protocol code, not availability of Discord, multicast networks or Sentry in a user's deployment.

## Discord Rich Presence

Enable it in Desktop settings with a valid Discord application ID. The native Desktop process opens Discord's local `discord-ipc-N` socket/pipe and sends an acknowledged `SET_ACTIVITY`. Desktop refreshes the activity every 30 seconds; it recreates the connection after the Discord process restarts. When disabled, Desktop explicitly clears activity. No Discord bot token is used.

CLI: `nl discord presence --application-id 123456789012345678 --details 'Minecraft' --state 'Playing' --interactive`. Write newline-separated JSON activities to stdin (`null` clears). Activity updates wait for an IPC acknowledgement; if IPC dies during an update the CLI reconnects and resends once. An idle interactive session refreshes every 60 seconds. A rejected Discord command is returned as an error, **not** retried. Shutdown attempts to clear presence. Interactive stdin must come from a trusted process because it controls publicly visible presence text/URLs.

A Discord desktop process and a registered Discord app are required for an actual public Rich Presence. A CI Unix socket is only a local IPC protocol test. The built-in Rust Desktop frontend is tested separately from the Go CLI.

## DNS-SD / mDNS

Publisher: `nl lan publish --instance MyNetwork --url https://192.168.1.5:19443 --fingerprint <leaf-cert-sha256>`; verify the HTTPS endpoint is already live before announcing. Discovery: `nl lan discover --timeout 5s`. Verification: `nl lan verify --url https://192.168.1.5:19443 --pin <independently-obtained-leaf-cert-sha256>`.

The publisher binds its outbound UDP socket to the selected local address rather than the system's arbitrary default source address. Only successful DNS answer messages with the expected DNS class and non-loopback IPv4 addresses are accepted as advertisements. Discovery results remain **unverified** until an independent administrator-configured TLS certificate pin matches. The mDNS TXT `fp` is never accepted as its own trust anchor. IPv4 multicast 224.0.0.251:5353 must be allowed by the host, interface and firewall. An external DNS-SD implementation may split PTR/SRV/TXT/A records into separate responses; the discovery parser currently requires these records in the same response (the bundled publisher sends them together). This limit must be resolved before claiming universal Bonjour interoperability.

## Sentry

Backend requires an explicit `LAUNCHER_SENTRY_BACKEND_ENABLED=true` and `LAUNCHER_SENTRY_BACKEND_DSN=<dsn>`; no telemetry is emitted by default. The Desktop requires an explicit user consent flag and a configured Desktop DSN. The Backend captures redacted bounded error diagnostics, not user request bodies, headers or authentication tokens. The Desktop sends only allowlisted JavaScript asset frames or a fixed native panic category.

A transient HTTP 429/502/503/504 response is retried at most twice under a three-second request deadline, retaining the same event ID; bounded `Retry-After` is respected. On Backend shutdown the queue is drained for no longer than five seconds before exiting. Sentry remains best effort: transport failure, queue overflow and host crashes can still lose diagnostics. No sensitive payload is placed in a persistent retry spool. Configure data handling, DSN access, firewall and retention on the Sentry destination.

## Verification boundary

The repository tests: live Unix IPC framing and restart, DNS-SD reply validation and actual TLS leaf pinning, HTTP Sentry envelope ingestion/retry/drain. A real same-host UDP multicast publish/discover plus pinned TLS endpoint has passed on Linux; the optional integration test can be repeated via `LAUNCHER_LAN_E2E=1 go test ./internal/lanmdns -run TestLiveLANPublishDiscoverAndPinnedTLS0429` from `cli/`. These tests do not replace acceptance with a running Discord account/application, a physical two-host multicast LAN, and a real Sentry tenant. These external checks plus six-platform release verification remain required before production certification.
