# polar-sdk

Go SDK for building plugins on the [Polar](https://github.com/networkextension/Polar) platform.

Provides:

- `sdk.Client` — HMAC-signed HTTP client for talking to dock's `/internal/v1/*` surface
- `sdk.NewClient(dockBase, pluginName, hmacKey)` — constructor
- `sdk.DeriveHMACKey(plaintextToken)` — derives the signing key from the plugin token issued by dock
- Cached lookups: `AuthVerify(token)`, `UserGet(id)`, `TeamGet(id)` (30s TTL)
- Uncached lookups for sensitive data: `LLMConfigGet`, `BotUserGet`, `ChatThreadGet`, `AgentPresenceGet`
- Dispatch helpers: `AgentDispatch`, `AgentLLMCallRecord`, `VideoShotCallRecord`
- Token/host sync (v0.2.2): `IssueAgentToken`, `IssueHost` — plugins that mint agent tokens locally call these to dual-write into dock's canonical tables (fixes the polar-hosts split-brain)
- Tenant access: `WorkspacePluginAccess(workspaceID, plugin)` — closed-by-default; root team always allowed
- `Heartbeat` — plugin → dock liveness signal

## Install

```bash
go get github.com/networkextension/polar-sdk@latest
```

## Usage

```go
import "github.com/networkextension/polar-sdk"

dock := sdk.NewClient(
    "https://dock.example.com",       // POLAR_DOCK_URL
    "iosdist",                         // plugin name (matches plugin_modules.name)
    sdk.DeriveHMACKey(os.Getenv("POLAR_PLUGIN_TOKEN")),
)

// session introspection (cached 30s)
res, err := dock.AuthVerify(bearerToken)
if err != nil { /* invalid session */ }
fmt.Println(res.UserID, res.Role, res.WorkspaceID)
```

## Versioning

`v0.x.y` — unstable. API may change between minor versions.
`v1.0.0` — first stable release, planned alongside Polar's open-source release.

## Related

- [Polar dock](https://github.com/networkextension/Polar) — identity + LLM proxy + plugin platform
- [open-platform.md](https://github.com/networkextension/Polar/blob/main/doc/arch/open-platform.md) — plugin model ADR
- [auth-and-tokens.md](https://github.com/networkextension/Polar/blob/main/doc/arch/auth-and-tokens.md) — token model ADR
- [internal-api-v1.md](https://github.com/networkextension/Polar/blob/main/doc/arch/internal-api-v1.md) — `/internal/v1/*` endpoint spec

## License

MIT
