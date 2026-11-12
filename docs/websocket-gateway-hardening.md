# WebSocket gateway safety and capacity limits

ActivityPods already uses the open-source `ws` WebSocket implementation inside
its Moleculer API gateway. Keeping `ws` avoids a disruptive protocol or
client change; the principal risks were in the gateway's connection lifecycle,
unbounded frames and message handling, rather than the choice of library.

## Changes

- One `WebSocketServer` instance per provider gateway. The old implementation
  accidentally constructed a second, unused server for every connection.
- At most 2,048 established or pending upgrades per gateway process, with
  a 10-second handshake budget. Global caps are per node, not per account
  or entire cluster.
- The inbound `ws` message limit is 64 KiB. Per-message compression is off
  to avoid unnecessary CPU/memory cost and compression side channels.
- Browser handshake `Origin` must exactly match the configured provider
  origin, frontend origin or an explicitly trusted additional origin.
  Third-party Solid frontends must be allowlisted through the
  comma-separated `APODS_WS_ALLOWED_ORIGINS` environment variable.
  Non-browser clients without `Origin` still need route authentication.
  HTTP CORS policy does not authorize WebSocket upgrades.
- A 30-second ping/pong sweep terminates dead connections. Connection
  bookkeeping uses a `Set` so removal is constant-time; gateway shutdown
  closes its listener and active sockets.
- Per connection, at most eight asynchronous incoming handlers and
  256 messages in a ten-second window. A connection whose queued outbound
  bytes exceed 1 MiB is closed instead of retaining an unbounded backlog.
  The `connection.send` callback retains the correct underlying socket
  receiver.
- Handshake errors, callback errors and closed sockets cannot leave
  unobserved promise rejections or leaked connection bookkeeping. Gateway
  logs omit the original URL and query parameters, which may contain tokens.
- Extra socket error/close handlers are removed once the request settles.

## Compatibility and deployment

WebSocket protocol remains RFC 6455; existing `ws` clients need not move
to Socket.IO or a new transport. However, applications that previously
connected with an untrusted browser Origin will now be refused and must
be explicitly allowed by the provider. The 64 KiB message ceiling and
per-connection limits may need reviewed exceptions for large legitimate
payloads; large media should use upload endpoints instead of WebSockets.

The gateway's pre-existing authentication/authorization pipeline remains
responsible for verifying credentials and per-topic permissions. This
hardening does not replace authentication, device session revocation or
stream-specific authorization checks.

## Capacity acceptance still required

This PR includes regression tests for origin rejection, frame and
connection limits, callback cleanup, backpressure and inbound concurrency.
Before declaring production throughput, run controlled real TLS
handshakes through the deployed proxy with multiple authenticated users
and measure handshake p95/p99, retained RSS per connection, reconnect
rate, ping latency, event-loop delay, send queue/slow-consumer eviction,
and error rates. For clustered deployments also verify reverse proxy
Upgrade headers, consistent routing, token expiry and per-user quotas.

Sources: [ws documentation](https://github.com/websockets/ws#readme),
[ws server API](https://github.com/websockets/ws/blob/master/doc/ws.md)
and [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html).
