/**
 * Docker image discovery (optional, opt-in).
 *
 * Enumerates the container images already present on the Docker host by talking
 * to the Docker Engine API over its Unix socket, so an operator can pick one and
 * kick off a Trivy scan without typing the reference by hand.
 *
 * This module only ever issues GET requests (/containers/json, /images/json).
 * It requires the Docker socket to be mounted into the backend container, which
 * is NOT done by default — see compose.prod.yaml and the security note there.
 * When the socket is absent (the default), discoverImages() returns
 * { available: false } so the UI can show guidance instead of erroring.
 */

import http from 'http';
import fs from 'fs';

const DEFAULT_SOCKET = '/var/run/docker.sock';

export interface DiscoveredImage {
  image: string; // human-friendly ref the container was created from, e.g. "nginx:latest"
  image_id: string; // sha256 image id
  containers: string[]; // container names using this image
  running: number; // how many of those containers are currently running
  scannable: boolean; // ref looks like something Trivy can pull
}

export interface DiscoveryResult {
  available: boolean;
  reason?: string;
  images: DiscoveredImage[];
}

interface DockerContainer {
  Names?: string[];
  Image?: string;
  ImageID?: string;
  State?: string;
}

function socketPath(): string {
  return process.env.DOCKER_SOCKET_PATH || DEFAULT_SOCKET;
}

// Minimal GET-over-unix-socket helper. We deliberately avoid adding a Docker
// client dependency for two read-only calls.
function dockerGet(path: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { socketPath: socketPath(), path, method: 'GET', timeout: 5000 },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          const status = res.statusCode || 0;
          if (status >= 200 && status < 300) {
            try {
              resolve(JSON.parse(body || 'null'));
            } catch {
              reject(new Error('Docker API returned invalid JSON'));
            }
          } else {
            reject(Object.assign(new Error(`Docker API responded ${status}`), { statusCode: status }));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Docker API request timed out')));
    req.on('error', reject);
    req.end();
  });
}

// Same conservative whitelist the Trivy scanner uses, minus bare image IDs:
// scanning a container's local sha256 id isn't meaningful for a registry pull.
const IMAGE_REF_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,510}$/;
function isScannable(ref: string): boolean {
  if (!ref || !IMAGE_REF_RE.test(ref)) return false;
  if (ref.startsWith('sha256:')) return false;
  if (/^[0-9a-f]{12,64}$/i.test(ref)) return false; // bare hex id
  return true;
}

export class DockerDiscovery {
  /** True if the Docker socket file is present (mount configured). */
  static socketPresent(): boolean {
    try {
      return fs.existsSync(socketPath());
    } catch {
      return false;
    }
  }

  /**
   * Return the deduplicated set of images backing the host's containers, newest
   * usage first. Never throws — connectivity/permission problems are surfaced as
   * { available: false, reason }.
   */
  static async discoverImages(): Promise<DiscoveryResult> {
    if (!this.socketPresent()) {
      return {
        available: false,
        reason:
          'Docker socket not available. Mount /var/run/docker.sock into the backend container to enable image discovery (see deployment docs — this grants Docker access and is opt-in).',
        images: [],
      };
    }

    let containers: DockerContainer[];
    try {
      // all=1 includes stopped containers so previously-pulled images still show.
      containers = (await dockerGet('/containers/json?all=1')) || [];
    } catch (err: any) {
      const code = err?.code || err?.statusCode;
      const reason =
        code === 'EACCES'
          ? 'Permission denied reading the Docker socket. The backend user must be able to read /var/run/docker.sock.'
          : `Could not reach the Docker API: ${err?.message || 'unknown error'}`;
      return { available: false, reason, images: [] };
    }

    // Group containers by the image ref they were created from.
    const byImage = new Map<string, DiscoveredImage>();
    for (const c of containers) {
      const image = (c.Image || '').trim();
      if (!image) continue;
      const name = (c.Names?.[0] || '').replace(/^\//, '') || '(unnamed)';
      const entry =
        byImage.get(image) ||
        ({
          image,
          image_id: c.ImageID || '',
          containers: [],
          running: 0,
          scannable: isScannable(image),
        } as DiscoveredImage);
      if (!entry.containers.includes(name)) entry.containers.push(name);
      if ((c.State || '').toLowerCase() === 'running') entry.running += 1;
      if (!entry.image_id && c.ImageID) entry.image_id = c.ImageID;
      byImage.set(image, entry);
    }

    // Running images first, then by container count, then name — most relevant on top.
    const images = Array.from(byImage.values()).sort(
      (a, b) =>
        b.running - a.running ||
        b.containers.length - a.containers.length ||
        a.image.localeCompare(b.image)
    );

    return { available: true, images };
  }
}
