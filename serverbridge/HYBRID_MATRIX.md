# ServerBridge hybrid core certification matrix — 0.19.10

Hybrid cores are **not** covered by the Universal Server Adapter release cohort. A Bukkit/Forge/Fabric-compatible API surface is not sufficient evidence that login interception, scheduler ownership, lifecycle, telemetry, or control semantics are equivalent.

| Core | 0.19.10 status | Universal adapter fallback |
|---|---|---|
| Mohist | not certified | denied |
| Arclight | not certified | denied |
| Magma | not certified | denied |
| CatServer | not certified | denied |
| Banner | not certified | denied |
| Cardboard | not certified | denied |

A hybrid may move to `certified` only through a separately versioned target, its own artifact hash namespace, runtime login/control/event tests, and explicit evidence in this matrix. It must never inherit certification from `bukkit`, `paper`, `fabric`, `forge`, or `neoforge`.
