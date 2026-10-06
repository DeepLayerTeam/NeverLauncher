# NeverExtensions SDK 0.21.0

This directory is the source-of-truth SDK shipped with NeverLauncher 0.21.0.

- `backend/go` — authenticated Extension Host Protocol client, capabilities, logs, heartbeat and event/hook callbacks.
- `admin/typescript` — typed sandboxed Admin `postMessage` bridge.
- `desktop/typescript` — typed sandboxed Desktop/Tauri-broker bridge.
- `desktop/rust` — generated Desktop protocol types for native companion code, without privileged Tauri access.
- `cli/go` — authenticated CLI target application/command SDK.
- `api/extension-host-protocol.json` — canonical protocol type source used by `scripts/sdk/generate-types.py`.

Developer lifecycle:

```sh
nl extension init --target backend,admin,desktop,cli --out my-extension
nl extension build my-extension
nl extension test my-extension
nl extension dev my-extension --target backend --grant telemetry:write
```

`NEVERLAUNCHER_SDK_ROOT` or `--sdk-root` can point builds at a local SDK checkout. Without it, standard Go module resolution is used.
