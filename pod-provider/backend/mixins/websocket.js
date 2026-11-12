const { WebSocketServer, WebSocket } = require('ws');
const {
  MAX_INBOUND_BYTES, MAX_CONNECTIONS, HEARTBEAT_MS, MAX_ASYNC_MESSAGES,
  allowedOrigins, isAllowedOrigin, canAcceptConnection, canBufferMessage,
  outboundSize, createSendBudget, isAllowedCapabilityOrigin
} = require('../utils/websocket-safety');
const http = require('http');
const urlJoin = require('url-join');
/**
 * This mixin adds the ability to create WebSocket routes to the moleculer-web API Gateway.
 * The mixin adds a new action `addWebSocketRoute` to the service.
 * The action takes the following parameters:
 * - name: The name of the route.
 * - route: The route path.
 * - authorization: Whether to require authorization.
 * - authentication: Whether to require authentication.
 * - use: An array of middleware functions to use.
 * - handlers: An object with the following webSocket event callbacks:
 * - onConnection: (connection)
 * - onClose: (event, connection)
 * - onMessage: (message, connection)
 * - onError: (event, connection)
 * @type {import('moleculer').ServiceSchema}
 */
module.exports = {
  name: 'websocket',
  settings: {
    baseUrl: null
  },
  created() {
    /** @type {import("./websocket").Connection[]} */
    this.connections = [];
    this.connectionIndexes = new Map();
    this.pendingWsUpgrades = 0;
    this.wsSendBudget = createSendBudget();
    this.wsPendingSends = new Map();
    this.wsAllowedOrigins = null;
    if (!this.settings.baseUrl) throw new Error('The websocket api mixin requires the `baseUrl` setting.');
  },
  started() {
    // Listen to upgrade requests and handle them with `upgradeHandler`.
    // This will attach a `webSocketRequestHandler` to upgrade the
    // connection and get a web socket object.
    this.wsAllowedOrigins = allowedOrigins(
      this.settings.baseUrl,
      this.settings.frontendUrl,
      process.env.APODS_WS_ALLOWED_ORIGINS
    );
    this.wss = new WebSocketServer({
      noServer: true,
      maxPayload: MAX_INBOUND_BYTES,
      perMessageDeflate: false
    });
    this.wsHeartbeat = setInterval(() => {
      for (const ws of this.wss?.clients || []) {
        if (ws.readyState !== WebSocket.OPEN) continue;
        if (ws.__apodsHeartbeatAlive === false) {
          ws.terminate();
          continue;
        }
        ws.__apodsHeartbeatAlive = false;
        try { ws.ping(); } catch { ws.terminate(); }
      }
    }, HEARTBEAT_MS);
    this.wsHeartbeat.unref?.();
    this.server.on('upgrade', this.upgradeHandler);
  },
  stopped() {
    if (this.wsHeartbeat) clearInterval(this.wsHeartbeat);
    this.wsHeartbeat = null;
    this.server?.off('upgrade', this.upgradeHandler);
    if (this.wss) {
      for (const client of this.wss.clients) client.terminate();
      this.wss.close();
      this.wss = null;
    }
    // Release outstanding reservations even when ws send callbacks never
    // fire (e.g. TCP reset or forced shutdown).
    for (const reservations of this.wsPendingSends.values()) {
      for (const release of reservations) release();
    }
    this.wsPendingSends.clear();
    this.connections.length = 0;
    this.connectionIndexes.clear();
    this.pendingWsUpgrades = 0;
  },
  actions: {
    // TODO: support interval-based pings?
    /** See description in service comment. */
    addWebSocketRoute: {
      params: {
        name: { type: 'string' },
        route: { type: 'string' },
        authorization: { type: 'boolean', default: false },
        authentication: { type: 'boolean', default: false },
        use: { type: 'array', items: 'function', default: [] },
        handlers: {
          $$type: 'object',
          onConnection: { type: 'function', default: () => {} },
          onClose: { type: 'function', default: () => {} },
          onMessage: { type: 'function', default: () => {} },
          onError: { type: 'function', default: () => {} }
        }
      },
      async handler(ctx) {
        const { name, route, authorization, authentication, use, handlers } = ctx.params;

        // Use the service's regular route handler but add some mixins.
        this.actions.addRoute({
          route: {
            name,
            authorization,
            authentication,
            path: route,
            bodyParsers: false,
            callOptions: { timeout: 0 },
            aliases: {
              'GET /': [
                // Add provided mixins.
                ...use,
                // Handle the upgrade and register the callbacks (or error on non-ws requests).
                (request, response, next) => this.handleWsRequest(request, response, next, handlers),
                // The alias route array needs to have an action after the middleware functions.
                `${this.name}.onWsConnection`
              ]
            },
            // Prevent ws connections from being closed by the lifecycle methods.
            onAfterCall: (ctx, bla, incomingRequest, serverResponse) =>
              this.delayConnectionClosing(incomingRequest, serverResponse)
          }
        });
      }
    },
    onWsConnection(ctx) {
      // Just a dummy function to satisfy the alias middleware handler above.
      // You can access the connection object with `ctx.meta.connection`.
      // Warning: This action is also called, if the connection fails.
      // In this case, `ctx.meta.connection` is unset.
    }
  },

  methods: {
    /**
     * @param {import('moleculer-web').IncomingMessage} request The moleculer-web request.
     * @param {import('http').ServerResponse} response The node http server response.
     * @param {() => void} next The next callback.
     * @param {import("./websocket").WebSocketHandlers} handlers The handlers to register.
     */
    async handleWsRequest(request, response, next, handlers) {
      if (!request.webSocketRequestHandler) {
        response.statusCode = 426;
        response.statusMessage = 'Upgrade Required: Not a WebSocket request';
        next();
        return;
      }
      if (!canAcceptConnection(this.connections.length, this.pendingWsUpgrades)) {
        response.statusCode = 503;
        response.statusMessage = 'WebSocket capacity reached';
        next();
        return;
      }
      // Count handshakes as well as accepted clients: concurrent upgrades
      // cannot slip past the per-node cap before registration completes.
      this.pendingWsUpgrades++;
      let webSocket;
      try {
        webSocket = await request.webSocketRequestHandler();
      } catch {
        response.statusCode = 400;
        response.statusMessage = 'WebSocket handshake failed';
        next();
        return;
      } finally {
        this.pendingWsUpgrades--;
      }
      webSocket.__apodsHeartbeatAlive = true;
      webSocket.on('pong', () => { webSocket.__apodsHeartbeatAlive = true; });

      // Apply the same queue bound to direct webSocket.send() callers and
      // connection.send(). A slow client cannot retain unlimited outbound
      // messages or consume the memory budget of healthy peers.
      const rawSend = webSocket.send.bind(webSocket);
      const reservations = new Set();
      this.wsPendingSends.set(webSocket, reservations);
      webSocket.send = (payload, ...args) => {
        const bytes = outboundSize(payload);
        const release = canBufferMessage(webSocket, payload) ?
          this.wsSendBudget.reserve(bytes) : null;
        if (!release) {
          const callback = args.find(value => typeof value === 'function');
          if (callback) callback(new Error('WebSocket outbound queue limit'));
          webSocket.terminate();
          return;
        }
        reservations.add(release);
        const callback = args.length && typeof args[args.length - 1] === 'function'
          ? args.pop() : null;
        const done = error => {
          release();
          reservations.delete(release);
          if (callback) callback(error);
        };
        try {
          return rawSend(payload, ...args, done);
        } catch (error) {
          done(error);
          throw error;
        }
      };

      // Create a new connection object (passed to all event handlers).
      const wsBase = this.settings.baseUrl.replace(/^http/, 'ws');
      /** @type {import("./websocket").Connection} */
      const connection = {
        server: this.wss,
        request,
        response,
        // The registered route (e.g. <wsBase>/sockets/:foo)
        baseUrl: urlJoin(wsBase, request.baseUrl),
        // The URL path as requested by the client (including URL params, e.g. <wsBase>/sockets/bar1?p2=v2).
        requestUrl: urlJoin(wsBase, request.originalUrl),
        // The parsed URL path without URL params (e.g. <wsBase>/sockets/bar1).
        parsedUrl: urlJoin(wsBase, request.parsedUrl),
        // The context params (URL params + registered params (e.g. {foo: "bar1", p2: "v2"}))
        params: request.$params,
        webSocket,
        send: webSocket.send.bind(webSocket)
      };

      // Add event listeners registered by the caller.
      const safeHandler = (name, ...args) => {
        try {
          const result = handlers[name](...args);
          if (result && typeof result.then === 'function') {
            Promise.resolve(result).catch(() => webSocket.terminate());
          }
        } catch { webSocket.terminate(); }
      };
      webSocket.addEventListener('close', e => safeHandler('onClose', e, connection));
      let inflightMessages = 0;
      webSocket.addEventListener('message', e => {
        if (inflightMessages >= MAX_ASYNC_MESSAGES) {
          webSocket.terminate();
          return;
        }
        inflightMessages++;
        try {
          const result = handlers.onMessage(e.data, connection);
          if (result && typeof result.then === 'function') {
            Promise.resolve(result).catch(() => webSocket.terminate())
              .finally(() => { inflightMessages--; });
          } else {
            inflightMessages--;
          }
        } catch {
          inflightMessages--;
          webSocket.terminate();
        }
      });
      webSocket.addEventListener('error', e => safeHandler('onError', e, connection));

      // Swap-delete in O(1), preserving the existing connections array API.
      webSocket.addEventListener('close', () => {
        const index = this.connectionIndexes.get(connection);
        if (index === undefined) return;
        const last = this.connections.pop();
        if (last && last !== connection) {
          this.connections[index] = last;
          this.connectionIndexes.set(last, index);
        }
        this.connectionIndexes.delete(connection);
        for (const release of reservations) release();
        reservations.clear();
        this.wsPendingSends.delete(webSocket);
      });

      this.connectionIndexes.set(connection, this.connections.length);
      this.connections.push(connection);
      safeHandler('onConnection', connection);

      // Attach connection to ctx.
      request.$ctx.meta.connection = connection;

      // Handle next middleware.
      next();

      this.logger.debug('WebSocket connection accepted on route: %s', request.baseUrl);
    },

    /**
     * Inspired by https://codeberg.org/kitten/app/src/branch/main/src/Server.js#L1042
     * @param {http.IncomingMessage} request The request
     * @param {import('node:net').Socket} socket The socket
     * @param {Buffer} head The first packet of the request
     * @returns  {object} `this.httpHandler(request, response)`
     */
    upgradeHandler(request, socket, head) {
      // Browser WebSockets send Origin even when they cannot send custom
      // Authorization headers. Block cross-site cookie-backed upgrades
      // before invoking the route middleware or allocating a WebSocket.
      if (!(isAllowedOrigin(request.headers.origin, this.wsAllowedOrigins) ||
            isAllowedCapabilityOrigin(request.headers.origin, request.url)) ||
          head.length > MAX_INBOUND_BYTES ||
          !canAcceptConnection(this.connections.length, this.pendingWsUpgrades)) {
        if (!socket.destroyed) {
          socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        }
        return;
      }
      socket.setNoDelay?.(true);
      const response = new http.ServerResponse(request);
      response.assignSocket(socket);

      // Avoid hanging onto upgradeHead as this will keep the entire
      // slab buffer used by node alive.
      const copyOfHead = Buffer.alloc(head.length);
      head.copy(copyOfHead);

      response.on('finish', () => {
        if (response.socket !== null) {
          response.socket.destroy();
        }
      });

      // Add a handler that indicates a web socket request.
      // Calling the handler will perform the ws upgrade handshake and return the webSocket.
      request.webSocketRequestHandler = () =>
        new Promise((resolve, reject) => {
          try {
            if (!this.wss) throw new Error('WebSocket server unavailable');
            this.wss.handleUpgrade(request, request.socket, copyOfHead, ws => {
              this.wss?.emit('connection', ws, request);
              resolve(ws);
            });
          } catch (error) {
            reject(error);
          }
        });

      return this.httpHandler(request, response);
    },

    /**
     * Delay the connection closing until the web socket is closed, if this is a websocket connection.
     * @param {import('moleculer-web').IncomingMessage} incomingRequest The incoming moleculer-web request.
     * @param {import('http').ServerResponse} serverResponse The node http server response.
     */
    async delayConnectionClosing(incomingRequest, serverResponse) {
      // Don't return, if this is an open websocket, otherwise the connection will be closed.
      if (incomingRequest.webSocketRequestHandler) {
        // Only resolve, once the socket closes.
        await new Promise((resolve, reject) => {
          serverResponse.socket.on('close', resolve);
          serverResponse.socket.on('error', reject);

          // If already closed, return immediately.
          if (serverResponse.socket.closed) {
            resolve();
          }
        });
      }
    }
  }
};
