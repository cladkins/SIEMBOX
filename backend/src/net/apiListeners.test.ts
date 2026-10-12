/**
 * The API listeners: the proxy socket's file handling, its sentinel peer, and
 * the TCP server pinning each connection's peer address. Hermetic: sockets live
 * in a fresh temporary directory, TCP on 127.0.0.1:0. Run with `npm test`
 * (tsx --test).
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { PROXY_SOCKET_PEER } from './clientAddress';
import { createApiServer, listenProxySocket, proxySocketState, stopListening } from './apiListeners';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-listeners-'));
const servers: http.Server[] = [];
after(() => {
  for (const server of servers) stopListening(server);
  fs.rmSync(dir, { recursive: true, force: true });
});

const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined } as never;

/** Answers with the connection's remoteAddress. */
const echoPeer: http.RequestListener = (req, res) => {
  res.end(JSON.stringify({ peer: req.socket.remoteAddress ?? null }));
};

function get(options: http.RequestOptions): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('the proxy socket is mode 0666 and stamps its connections with the sentinel peer', async () => {
  const socketPath = path.join(dir, 'api.sock');
  const { server, state } = await listenProxySocket(echoPeer, socketPath, quiet);
  assert.ok(server);
  servers.push(server);
  assert.deepEqual(state, { state: 'listening', path: socketPath });
  assert.deepEqual(proxySocketState(), state);
  const stat = fs.lstatSync(socketPath);
  assert.ok(stat.isSocket());
  assert.equal(stat.mode & 0o777, 0o666, 'nginx workers (uid 101) must be able to connect');
  const res = await get({ socketPath, path: '/' });
  assert.deepEqual(JSON.parse(res.body), { peer: PROXY_SOCKET_PEER });

  stopListening(server);
  await once(server, 'close');
  assert.equal(fs.existsSync(socketPath), false, 'closing removes the socket file');
});

test('a socket file left behind by an earlier run is replaced', async () => {
  const socketPath = path.join(dir, 'stale.sock');
  // A socket inode nobody listens on: listen under another name, move it
  // into place, then close (which only removes the original name).
  const holder = net.createServer();
  const temp = path.join(dir, 'holder.sock');
  holder.listen(temp);
  await once(holder, 'listening');
  fs.renameSync(temp, socketPath);
  holder.close();
  await once(holder, 'close');
  assert.ok(fs.lstatSync(socketPath).isSocket(), 'a stale socket file is in place');

  const { server, state } = await listenProxySocket(echoPeer, socketPath, quiet);
  assert.ok(server);
  servers.push(server);
  assert.equal(state.state, 'listening');
  const res = await get({ socketPath, path: '/' });
  assert.equal(res.status, 200);
});

test('anything other than a socket at the path is left alone and refused, and TCP keeps working', async () => {
  const socketPath = path.join(dir, 'not-a-socket');
  fs.writeFileSync(socketPath, 'keep me');
  const { server, state } = await listenProxySocket(echoPeer, socketPath, quiet);
  assert.equal(server, null);
  assert.equal(state.state, 'error');
  assert.match((state as { error: string }).error, /not a socket/);
  assert.equal(fs.readFileSync(socketPath, 'utf8'), 'keep me');

  const tcp = createApiServer(echoPeer);
  servers.push(tcp);
  tcp.listen(0, '127.0.0.1');
  await once(tcp, 'listening');
  const res = await get({ host: '127.0.0.1', port: (tcp.address() as AddressInfo).port, path: '/' });
  assert.deepEqual(JSON.parse(res.body), { peer: '127.0.0.1' });
});

test('without its directory (the volume is not mounted) the socket is skipped, not created', async () => {
  const missing = path.join(dir, 'no-such-volume');
  const { server, state } = await listenProxySocket(echoPeer, path.join(missing, 'api.sock'), quiet);
  assert.equal(server, null);
  assert.deepEqual(state, { state: 'no-volume', path: path.join(missing, 'api.sock'), directory: missing });
  assert.equal(fs.existsSync(missing), false);
});

test('SIEMBOX_PROXY_SOCKET=off and a relative path', async () => {
  assert.deepEqual((await listenProxySocket(echoPeer, 'off', quiet)).state, { state: 'off' });
  assert.deepEqual((await listenProxySocket(echoPeer, ' OFF ', quiet)).state, { state: 'off' });
  const relative = await listenProxySocket(echoPeer, 'run/api.sock', quiet);
  assert.equal(relative.server, null);
  assert.equal(relative.state.state, 'error');
});

test('a TCP client that resets after sending still has its address (pinned on accept)', async () => {
  const seen: Array<string | null> = [];
  const tcp = createApiServer((req, res) => {
    // Read the address only after the client is gone.
    setTimeout(() => {
      seen.push(req.socket.remoteAddress ?? null);
      res.destroy();
    }, 100);
  });
  servers.push(tcp);
  tcp.listen(0, '127.0.0.1');
  await once(tcp, 'listening');
  const { port } = tcp.address() as AddressInfo;
  await new Promise<void>((resolve, reject) => {
    const client = net.connect(port, '127.0.0.1', () => {
      client.write('GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n', () => {
        setTimeout(() => {
          client.resetAndDestroy();
          resolve();
        }, 20);
      });
    });
    client.on('error', reject);
  });
  for (let i = 0; i < 50 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(seen, ['127.0.0.1']);
});
