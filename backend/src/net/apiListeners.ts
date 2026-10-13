/**
 * The API's two listeners, both serving the same Express app:
 *
 * - TCP :8421 for everything that calls the API directly: shippers, endpoint
 *   agents, scripts, and the web UI's nginx when the socket is unavailable.
 * - The proxy socket, SIEMBOX_PROXY_SOCKET (default /run/siembox/api.sock), a
 *   unix socket on the `api-socket` volume that only the backend and frontend
 *   containers mount. Connections on it are stamped with PROXY_SOCKET_PEER, the
 *   one peer whose X-Forwarded-For Express believes without configuration
 *   (trustedProxies.ts). Being able to connect is the credential: there is no
 *   address to pin and nothing a TCP client can forge.
 *
 * The socket is optional. It only listens when its directory already exists
 * (the volume is mounted; it is never created here), and if it cannot listen,
 * TCP and syslog carry on: nginx falls back to TCP on its own.
 */
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import type { Socket } from 'node:net';
import { logger } from '../utils/logger';
import { PROXY_SOCKET_PEER } from './clientAddress';

export const DEFAULT_PROXY_SOCKET = '/run/siembox/api.sock';

export type ProxySocketState =
  | { state: 'not-started' }
  | { state: 'off' }
  | { state: 'no-volume'; path: string; directory: string }
  | { state: 'listening'; path: string }
  | { state: 'error'; path: string; error: string };

let socketState: ProxySocketState = { state: 'not-started' };

/** What became of the proxy socket at startup, for diagnostics. */
export function proxySocketState(): ProxySocketState {
  return socketState;
}

type Log = Pick<typeof logger, 'info' | 'warn' | 'error'>;

function isDirectory(dir: string): boolean {
  try {
    return fs.statSync(dir).isDirectory();
  } catch {
    return false;
  }
}

/**
 * An HTTP server for the TCP listener. It reads each connection's peer address
 * as soon as the connection is accepted: Node otherwise asks the OS only when
 * something first reads remoteAddress, and once a client has reset the
 * connection that read returns undefined, which would leave the request with no
 * address to limit or log.
 */
export function createApiServer(app: http.RequestListener): http.Server {
  const server = http.createServer(app);
  server.on('connection', (socket: Socket) => void socket.remoteAddress);
  return server;
}

/**
 * Listens on the proxy socket at `socketPath` ('off' disables it). Never
 * throws: any problem is logged, recorded in proxySocketState(), and answered
 * with `server: null`.
 */
export async function listenProxySocket(
  app: http.RequestListener,
  socketPath: string | undefined = process.env.SIEMBOX_PROXY_SOCKET,
  log: Log = logger
): Promise<{ server: http.Server | null; state: ProxySocketState }> {
  const done = (state: ProxySocketState, server: http.Server | null = null) => {
    socketState = state;
    return { server, state };
  };
  const configured = (socketPath ?? '').trim() || DEFAULT_PROXY_SOCKET;
  if (configured.toLowerCase() === 'off') {
    log.info('Proxy socket off (SIEMBOX_PROXY_SOCKET=off): X-Forwarded-For is believed only from TRUSTED_PROXIES.');
    return done({ state: 'off' });
  }
  if (!path.isAbsolute(configured)) {
    const error = 'SIEMBOX_PROXY_SOCKET must be an absolute path';
    log.error(`Proxy socket not started: ${error} (got "${configured}").`);
    return done({ state: 'error', path: configured, error });
  }

  const directory = path.dirname(configured);
  if (!isDirectory(directory)) {
    // In a container this means an outdated compose file; on a development
    // machine it is the normal case.
    const inContainer = fs.existsSync('/.dockerenv') || fs.existsSync('/run/.containerenv');
    const message =
      `Proxy socket not started: ${directory} does not exist, so the api-socket volume is not mounted. ` +
      'The web UI still works (its nginx falls back to TCP), but update your compose file: with the volume, ' +
      'UI requests keep their real client addresses in every network mode. To run without the socket ' +
      "instead, set SIEMBOX_PROXY_SOCKET=off in the backend's environment.";
    if (inContainer) log.warn(message);
    else log.info(message);
    return done({ state: 'no-volume', path: configured, directory });
  }

  // A socket file left behind by a previous run (the volume outlives the
  // container) would make listen() fail with EADDRINUSE. Anything else at that
  // path is not ours to delete.
  try {
    const existing = fs.lstatSync(configured);
    if (!existing.isSocket()) {
      const error = `${configured} exists and is not a socket; refusing to replace it`;
      log.error(`Proxy socket not started: ${error}.`);
      return done({ state: 'error', path: configured, error });
    }
    fs.unlinkSync(configured);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      const error = (err as Error).message;
      log.error(`Proxy socket not started: ${error}.`);
      return done({ state: 'error', path: configured, error });
    }
  }

  const server = http.createServer(app);
  server.on('connection', (socket: Socket) => {
    Object.defineProperty(socket, 'remoteAddress', { value: PROXY_SOCKET_PEER, configurable: true, enumerable: true });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      // readableAll + writableAll: mode 0666, because the frontend's nginx
      // workers run as uid 101 while the backend runs as root.
      server.listen({ path: configured, readableAll: true, writableAll: true }, () => {
        server.off('error', reject);
        resolve();
      });
    });
  } catch (err) {
    const error = (err as Error).message;
    log.error(`Proxy socket not started: could not listen on ${configured}: ${error}. TCP keeps serving the API.`);
    return done({ state: 'error', path: configured, error });
  }
  server.on('error', (err) => log.error(`Proxy socket error: ${err.message}`));
  log.info(`Proxy socket listening on ${configured}`);
  return done({ state: 'listening', path: configured }, server);
}

/**
 * Stops accepting connections and drops idle keep-alive ones (closing the
 * proxy socket also removes its file). Requests still running are not waited
 * for.
 */
export function stopListening(server: http.Server | null | undefined): void {
  if (!server) return;
  server.close();
  server.closeIdleConnections();
}
