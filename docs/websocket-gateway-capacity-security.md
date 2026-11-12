# ActivityPods WebSocket gateway limits

The existing Node.js `ws` transport is retained. Changing the library
does not address the identified connection lifecycle and flow-control
issues, and would increase operational risk without measured benefit.

## Gateway changes

- Single shared `WebSocketServer({ noServer: true })` per API process.
  The previous per-handshake server allocation has been removed.
- Limit incoming messages to **256 KiB**, disable compression at the gateway,
  and require the browser handshake Origin to match the provider,
  frontend or explicitly configured `APODS_WS_ALLOWED_ORIGINS` list.
  Native clients without an Origin header continue through normal route
  authentication. Unknown origins cannot reuse cookie-backed sessions.
- Limit accepted plus pending upgrade handshakes to **2,048** per process.
  Track connection indexes for constant-time removal while retaining the
  existing connections-array API for callers.
- Ping every **30 seconds** and terminate clients that do not respond by
  the next heartbeat. Close clients and remove the upgrade event listener
  during service shutdown to avoid retained socket references.
- Bound the outbound WebSocket buffer to **2 MiB** per connection; slow
  peers are disconnected rather than retaining unbounded event data.
  Limit outstanding asynchronous message handlers to eight per client.
- Do not write the incoming request URL, which may contain access tokens,
  to connection logs.

These numbers are defensive defaults, **not** verified production tuning.
Client heartbeat/pong behavior is provided by the WebSocket protocol.

## Origin policy

`APODS_WS_ALLOWED_ORIGINS` accepts a comma-separated list of *canonical*
HTTP(S) origins (no wildcard, path, fragment, credentials or query).
The backend and frontend configured origins are included automatically.
Configure legitimate third-party Solid client origins explicitly if the
WebSocket handshake relies on browser credentials. Browser clients cannot
override their Origin header, but nonbrowser clients can; every private
route must still authenticate and authorize the principal.

## Remaining acceptance

Run authenticated real-browser Solid notifications and native clients
through HTTPS reverse proxy/CDN, including allowed third-party origins,
idle/mobile reconnect and token expiry. Measure capacity against 100,
1,000 and 2,000 concurrent sockets with actual p95/p99 publish latency,
heap/RSS, heartbeats, connection churn, backlog and dropped events.
Confirm Cloudflare/edge WebSocket upgrade and idle policies before
production rollout. For high fan-out, consider topic-aware sharding and
subscription authorization, not replacing `ws` merely for speed.


## Aggregate outbound memory

All WebSocket sends also reserve bytes against a **64 MiB total gateway
outbound queue budget** before entering the `ws` sender. A reservation
is released when the write callback fires or when the socket closes,
whichever happens first. Forced shutdown releases any remaining pending
reservations. This is a conservative queue budget across the full
2,048-connection process, not 2 MiB multiplied by every connection.
The budget does not include OS TCP buffers, inbound parsers or
application state; those still require real RSS profiling.


## Third-party Solid clients

The Solid Notifications Protocol permits browser clients from other
origins to connect to a `WebSocketChannel2023` receiveFrom URI. The
SemApps notification channel uses an opaque UUIDv4 receiveFrom path
and verifies that exact issued channel URI. The gateway therefore
permits cross-origin WebSocket handshakes **only** for this exact
capability route shape. Other routes still enforce the configured
Origin allowlist. Unknown/forged channel IDs are rejected by the
notification service itself; possession of a valid capability URL
authorizes that notification channel, not general Pod access.

The upstream SemApps notification implementation must also avoid
logging the full receiveFrom capability URL at DEBUG level and must
use valid WebSocket close codes. These are separate upstream
hardening items; the gateway itself no longer logs token-bearing
request URLs.
