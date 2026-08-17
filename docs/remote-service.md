# Remote multi-instance service

`xenoid-service` runs an authenticated control plane on an Apple Silicon Mac or
Linux ARM64 host. One process serves every initialized instance in one fixed
Xenoid project and exposes a scope-filtered MCP 2026-07-28 Streamable HTTP
endpoint.

The service is distinct from a remote Docker context. A Docker context lets a
local CLI control a remote engine; `xenoid-service` is the network service that
remote users and model clients connect to.

## Boundary and lifecycle

- One service process is fixed to one `XENOID_PROJECT`.
- It discovers instances under `<project>/.xenoid/instances/`.
- Every tool call except `xenoid_instances_list` requires an explicit
  `instance` argument.
- Every request re-resolves config, lease, runtime manager, and daemon client.
  External config changes are therefore visible without restarting the service.
- Mutations are serialized per instance in-process and across service processes.
  Different instances may run concurrently.
- `xenoid_up` invokes the canonical `./xenoid --instance NAME up` convergence
  path. It is the only remote operation that means the complete production
  runtime is ready.
- V1 operates initialized instances. Create or clone them with the local CLI;
  remote create, rename, delete, and lease release are intentionally absent.

The service must run as the same OS user, with the same `HOME`, project root,
Docker/Colima access, and private `~/.xenoid` state as the normal Xenoid CLI.
On macOS, use a user LaunchAgent rather than a root LaunchDaemon so the service
sees the operator's Colima VM and instance state.

## Create access

Initialize instances locally first:

```bash
./xenoid --instance phone-a init --config examples/config-macos-colima.json
./xenoid --instance phone-b init --from phone-a
```

Create a least-privilege token. The secret is printed once; the access store
contains only its SHA-256 digest and is kept under the ignored, mode-`0700`
`.xenoid/service/` directory.

```bash
./xenoid-service token create \
  --name observer \
  --instance phone-a \
  --scope read

./xenoid-service token create \
  --name operator \
  --all-instances \
  --scope read \
  --scope control
```

A named `--instance` grant is bound to that instance's immutable UUID, not only
its name. Recreating a name does not inherit the old grant. `--all-instances`
is an explicit wildcard and also grants access to instances initialized later.

Inspect or revoke metadata without printing secrets:

```bash
./xenoid-service token list
./xenoid-service token revoke observer
```

Scopes are cumulative:

| Scope | Capability |
| --- | --- |
| `read` | Authorized instance inventory and redacted status/health tools |
| `control` | `read` plus `up`, stop, proxy/location/input/app/device and OTA control |
| `root` | `read` plus explicit Android root-helper command execution |
| `inspect` | `read` plus explicit Frida start/stop |

`root` and `inspect` are not implied by `control`. Create separate tokens when
an analysis client genuinely needs those boundaries.

## Start safely

The safest default is loopback behind SSH, a private tunnel, or a TLS/OAuth
gateway:

```bash
./xenoid-service serve --bind 127.0.0.1 --port 8765
```

For direct network TLS, the private key must be a regular non-symlink file,
owned by the service user, with no group/other permission bits:

```bash
chmod 600 /secure/xenoid-service.key
./xenoid-service serve \
  --bind 0.0.0.0 \
  --port 8765 \
  --allow-host mcp.example.com \
  --allow-origin https://agent.example.com \
  --tls-cert /secure/xenoid-service.crt \
  --tls-key /secure/xenoid-service.key
```

A non-loopback bind fails unless direct TLS is configured by default. For a
temporary test on an explicitly trusted network, cleartext HTTP requires a
deliberate opt-in and still requires an exact Host allowlist:

```bash
./xenoid-service serve \
  --bind 0.0.0.0 \
  --port 8765 \
  --allow-host 192.0.2.10 \
  --allow-insecure-http
```

Clients connect to the host's actual LAN address, not `0.0.0.0`. This mode
marks startup as `transportSecurity: insecure-http`; bearer tokens and all MCP
traffic are visible in plaintext to the network. Do not use it on public,
shared, or untrusted networks, and revoke the test token afterwards.

`--allow-host` is required for non-loopback listeners and protects against DNS
rebinding and confused proxy routing. Repeat it for every externally forwarded
Host value. Browser clients also need an exact `--allow-origin`; requests that
do not carry an Origin header, such as server-to-server model clients, remain
valid. An unlisted Origin is rejected.

The built-in bearer tokens are deployment credentials, not an OAuth 2.1
authorization server. For a public endpoint, terminate TLS and standards-based
OAuth at a trusted gateway, keep Xenoid on loopback, and have the gateway replace
the external Authorization value with a dedicated private Xenoid bearer token
only on that loopback hop. Do not expose or return that private token to clients.

## MCP client

Configure the client with the service URL and inject the token through its
secret manager rather than committing it to a config file:

```json
{
  "mcpServers": {
    "xenoid-remote": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <secret-from-client-store>"
      }
    }
  }
}
```

The transport is stateless HTTP. Clients call `server/discover`, then
`tools/list`, then `xenoid_instances_list`; every instance tool includes a
required `instance` property with the MCP `Instance` parameter-header binding.
The service validates the 2026-07-28 request metadata and the
`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, and `Mcp-Param-Instance`
headers against the JSON body. It returns one `application/json` response per
POST; server-sent event streaming and GET sessions are not needed.

Those dynamic `Mcp-*` headers are emitted by a 2026-07-28-compatible MCP HTTP
transport, not by the static client configuration above. A client that only
implements an older Streamable HTTP revision will be rejected with a stable
protocol/header error; upgrade the client rather than hard-coding per-tool
headers in configuration.

Endpoints:

| Endpoint | Authentication | Purpose |
| --- | --- | --- |
| `POST /mcp` | Bearer token | MCP Streamable HTTP |
| `GET /v1/instances` | Bearer token with `read` | Authorized redacted inventory |
| `GET /healthz` | None, Host/Origin checks still apply | Process liveness only |

The remote MCP catalog is deliberately smaller than local `xenoid-mcp`.
Unrestricted host paths, host JavaScript, builds, packaging, deployment,
binderfs, kernel/eBPF changes, and credential-bearing proxy imports are never
network tools. Read tokens also never implicitly start or repair the daemon;
use `xenoid_up` explicitly before runtime-dependent calls.

## macOS LaunchAgent

Use absolute paths and replace `OPERATOR_HOME` and the project path. Save the plist
as `$HOME/Library/LaunchAgents/dev.xenoid.service.plist` while logged in as the user
who owns Colima and `~/.xenoid`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.xenoid.service</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/xenoid/xenoid-service</string>
    <string>--project</string><string>/opt/xenoid</string>
    <string>serve</string>
    <string>--bind</string><string>127.0.0.1</string>
    <string>--port</string><string>8765</string>
  </array>
  <key>WorkingDirectory</key><string>/opt/xenoid</string>
  <key>EnvironmentVariables</key>
  <dict><key>HOME</key><string>OPERATOR_HOME</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/xenoid-service.out.log</string>
  <key>StandardErrorPath</key><string>/tmp/xenoid-service.err.log</string>
</dict>
</plist>
```

Load it with
`launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.xenoid.service.plist"`
and inspect it with `launchctl print "gui/$(id -u)/dev.xenoid.service"`. Keep logs
in an operator-only location for production; the example `/tmp` paths are only
a starting point.

## Linux ARM64 systemd

Run under the existing Xenoid/Docker operator, never a different empty home:

```ini
[Unit]
Description=Xenoid multi-instance MCP service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=simple
User=xenoid
Group=xenoid
Environment=HOME=OPERATOR_HOME
WorkingDirectory=/opt/xenoid
ExecStart=/opt/xenoid/xenoid-service --project /opt/xenoid serve --bind 127.0.0.1 --port 8765
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

If Docker access is provided through a group, retain only that required group
with `SupplementaryGroups=`. A reverse proxy can publish the loopback endpoint;
preserve a configured Host value and apply the OAuth/token rules above.

## Operational notes

- Default limits are 1 MiB/request, 8 concurrent requests, 120 requests/minute
  per access name, and a 30-second socket timeout. TLS handshakes and HTTP
  headers have a separate five-second deadline; every response closes the
  connection. Connection and request admission also use bounded global,
  per-address (IPv6 `/64`), and active-connection limits. All operator-facing
  limits are configurable.
- Remote external commands inherit one absolute budget: 60 seconds for reads,
  900 seconds for ordinary mutations, and 7200 seconds for full `up`. Existing
  shorter backend/daemon timeouts still win.
- A second mutation for the same instance fails fast with `instance_busy`/HTTP
  503 instead of occupying a global worker while queued. Long `up` calls may
  continue while other instances are controlled normally.
- Tokens, daemon tokens, host paths, stdout/stderr, commands, URLs containing
  credentials, and private roots are removed from remote results.
- Token changes are visible immediately; restart is unnecessary.
- All resolved local CLI mutations, mutating fixed-instance stdio MCP calls,
  and remote service mutations share the same per-instance operation lock.
  CLI-backed `up`, Google-provider, and location mutations acquire and retain
  that lock in the child, so a service process exit cannot unlock an operation
  that is still running.
- Stop the service before moving the project or changing the operator user/HOME.

Run the runtime-free service contracts after changes:

```bash
python3 scripts/test-remote-service.py
python3 scripts/test-mcp-contract.py
```
