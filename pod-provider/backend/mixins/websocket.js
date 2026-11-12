const { WebSocketServer, WebSocket } = require('ws');

// Frame, connection and backpressure limits are deliberately static; they
// cannot be increased by client-supplied query parameters or headers.
const MAX_FRAME_BYTES = 64 * 1024;
const MAX_CONNECTIONS = 2048;
const MAX_BUFFERED_BYTES = 1024 * 1024;
const MAX_ACTIVE_HANDLERS = 8;
const MAX_MESSAGES_PER_10S = 256;
const HEARTBEAT_MS = 30000;
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
    this.connections = new Set();
    this.pendingUpgrades = 0;
    if (!this.settings.baseUrl) throw new Error('The websocket api mixin requires the `baseUrl` setting.');
    // Exact URL origins only. Browsers always send Origin on their
    // WebSocket handshakes. Third-party Solid frontends must be allowlisted.
    const configured = this.settings.wsAllowedOrigins || [this.settings.baseUrl];
    if (!Array.isArray(configured) || configured.length > 32) {
      throw new Error('WebSocket origin configuration must be a bounded list');
    }
    this.wsAllowedOrigins = new Set(configured.map(origin => {
      const url = new URL(origin);
      if (!['http:', 'https:'].includes(url.protocol) ||
          url.username || url.password || url.search || url.hash ||
          (process.env.NODE_ENV === 'production' && url.protocol !== 'https:')) {
        throw new Error('WebSocket origins must be trusted HTTP(S) origins');
      }
      return url.origin;
    }));
  },
  started() {
    // Listen to upgrade requests and handle them with `upgradeHandler`.
    // This will attach a `webSocketRequestHandler` to upgrade the
    // connection and get a web socket object.
    this.wss = new WebSocketServer({
      noServer: true,
      maxPayload: MAX_FRAME_BYTES,
      perMessageDeflate: false,
      clientTracking: true
    });
    this.wsHeartbeat = setInterval(() => {
      for (const ws of this.wss.clients) {
        if (ws.isAlive === false) {
          ws.terminate();
          continue;
        }
        ws.isAlive = false;
        if (ws.readyState === WebSocket.OPEN) ws.ping();
      }
    }, HEARTBEAT_MS);
    this.wsHeartbeat.unref?.();
    this.wss.on('connection', ws => {
      ws.isAlive = true;
      ws.on('pong', () => { ws.isAlive = true; });
    });
    this.server.on('upgrade', this.upgradeHandler);
  },
  stopped() {
    if (this.wsHeartbeat) {
      clearInterval(this.wsHeartbeat);
      this.wsHeartbeat = null;
    }
    this.server?.off('upgrade', this.upgradeHandler);
    for (const connection of this.connections) {
      connection.webSocket.terminate();
    }
    this.connections.clear();
    this.wss?.close();
    this.wss = null;
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
      // Reuse the single configured ws server. Constructing a separate
      // WebSocketServer on every connection created needless allocations.
      // The existence of the handler indicates, we can perform a WS handshake.
      // The call will do that and return the webSocket (see method `upgradeHandler`).
      let webSocket;
      try {
        webSocket = await request.webSocketRequestHandler();
      } catch {
        next(new Error('WebSocket handshake rejected'));
        return;
      }

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
        send: (...args) => {
          if (webSocket.readyState !== WebSocket.OPEN) return;
          if (webSocket.bufferedAmount > MAX_BUFFERED_BYTES) {
            webSocket.close(1013, 'Slow client');
            return;
          }
          // The legacy unbound webSocket.send loses its receiver when
          // called as connection.send; invoke on the socket explicitly.
          return webSocket.send(...args);
        }
      };

      // Bounded per-connection input. Async handlers must finish before new
      // work consumes the eight-slot budget; errors close the socket rather
      // than creating unhandled rejections.
      let activeHandlers = 0;
      let messagesInWindow = 0;
      let windowStarted = Date.now();
      const handlerFailed = () => {
        if (webSocket.readyState === WebSocket.OPEN) {
          webSocket.close(1011, 'Handler failed');
        }
      };
      webSocket.addEventListener('message', event => {
        const now = Date.now();
        if (now - windowStarted >= 10000) {
          windowStarted = now;
          messagesInWindow = 0;
        }
        messagesInWindow++;
        if (messagesInWindow > MAX_MESSAGES_PER_10S ||
            activeHandlers >= MAX_ACTIVE_HANDLERS) {
          webSocket.close(1008, 'Message rate exceeded');
          return;
        }
        activeHandlers++;
        try {
          Promise.resolve(handlers.onMessage(event.data, connection))
            .catch(handlerFailed)
            .finally(() => { activeHandlers--; });
        } catch {
          activeHandlers--;
          handlerFailed();
        }
      });
      webSocket.addEventListener('error', event => {
        try {
          Promise.resolve(handlers.onError(event, connection)).catch(() => {});
        } catch {
          // Client connection errors must never crash the API gateway.
        }
      });
      webSocket.addEventListener('close', event => {
        this.connections.delete(connection);
        try {
          Promise.resolve(handlers.onClose(event, connection)).catch(() => {});
        } catch {
          // Do not leave the socket registered if an app callback fails.
        }
      });
      this.connections.add(connection);
      request.$ctx.meta.connection = connection;

      try {
        Promise.resolve(handlers.onConnection(connection)).catch(handlerFailed);
      } catch {
        handlerFailed();
      }
      next();
      // Do not log requestUrl: query strings may contain bearer credentials.
      this.logger.debug('WebSocket connected', {
        activeConnections: this.connections.size
      });
    },

    /**
     * Inspired by https://codeberg.org/kitten/app/src/branch/main/src/Server.js#L1042
     * @param {http.IncomingMessage} request The request
     * @param {import('node:net').Socket} socket The socket
     * @param {Buffer} head The first packet of the request
     * @returns  {object} `this.httpHandler(request, response)`
     */
    upgradeHandler(request, socket, head) {
      const rejectUpgrade = status => {
        if (!socket.destroyed) {
          socket.end('HTTP/1.1 ' + status +
            '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        }
      };
      // Browser handshakes carry Origin; accept only exact trusted origins.
      // Non-browser clients may omit Origin but still pass route auth.
      const origin = request.headers.origin;
      if (origin !== undefined &&
          (typeof origin !== 'string' || !this.wsAllowedOrigins.has(origin))) {
        rejectUpgrade('403 Forbidden');
        return;
      }
      if (!this.wss || this.wss.clients.size + this.pendingUpgrades >= MAX_CONNECTIONS) {
        rejectUpgrade('503 Service Unavailable');
        return;
      }
      if (!Buffer.isBuffer(head) || head.length > MAX_FRAME_BYTES) {
        rejectUpgrade('413 Content Too Large');
        return;
      }

      this.pendingUpgrades++;
      let pending = true;
      let upgradeStarted = false;
      const releasePending = () => {
        if (!pending) return;
        pending = false;
        this.pendingUpgrades = Math.max(0, this.pendingUpgrades - 1);
        clearTimeout(timeout);
        socket.off('close', releasePending);
      };
      const timeout = setTimeout(() => {
        releasePending();
        socket.destroy();
      }, 10000);
      timeout.unref?.();
      socket.once('close', releasePending);

      const response = new http.ServerResponse(request);
      response.assignSocket(socket);
      const copyOfHead = Buffer.alloc(head.length);
      head.copy(copyOfHead);

      response.on('finish', () => {
        if (response.socket) response.socket.destroy();
      });
      request.webSocketRequestHandler = () => new Promise((resolve, reject) => {
        if (upgradeStarted || socket.destroyed || !this.wss) {
          reject(new Error('WebSocket upgrade not available'));
          return;
        }
        upgradeStarted = true;
        const failed = () => {
          reject(new Error('WebSocket upgrade closed'));
        };
        socket.once('close', failed);
        try {
          this.wss.handleUpgrade(request, socket, copyOfHead, ws => {
            socket.off('close', failed);
            releasePending();
            this.wss?.emit('connection', ws, request);
            resolve(ws);
          });
        } catch {
          socket.off('close', failed);
          releasePending();
          reject(new Error('Invalid WebSocket handshake'));
          socket.destroy();
        }
      });

      try {
        const result = this.httpHandler(request, response);
        if (result && typeof result.catch === 'function') {
          result.catch(() => {
            releasePending();
            socket.destroy();
          });
        }
        return result;
      } catch {
        releasePending();
        socket.destroy();
      }
    },

    /**
     * Delay the connection closing until the web socket is closed, if this is a websocket connection.
     * @param {import('moleculer-web').IncomingMessage} incomingRequest The incoming moleculer-web request.
     * @param {import('http').ServerResponse} serverResponse The node http server response.
     */
    async delayConnectionClosing(incomingRequest, serverResponse) {
      if (!incomingRequest.webSocketRequestHandler) return;
      const socket = serverResponse.socket;
      if (!socket || socket.destroyed) return;
      await new Promise((resolve, reject) => {
        const cleanup = () => {
          socket.off('close', closed);
          socket.off('error', failed);
        };
        const closed = () => { cleanup(); resolve(); };
        const failed = error => { cleanup(); reject(error); };
        socket.once('close', closed);
        socket.once('error', failed);
        if (socket.destroyed) closed();
      });
    }
  }
};
