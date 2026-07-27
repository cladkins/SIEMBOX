// tsc only compiles .ts -> .js; it silently ignores everything else under src/,
// so the log-discovery fingerprint library (fingerprints/*.yaml, its schema,
// and the onboard-template text files) needs an explicit copy into dist/ after
// build. Without this, a built image boots with an empty fingerprint library
// (fingerprintLoader reads relative to its own __dirname at runtime).
const fs = require('fs');
const path = require('path');

const SRC_DIR = path.join(__dirname, '../src/services/logDiscovery');
const DEST_DIR = path.join(__dirname, '../dist/services/logDiscovery');

const ASSETS = ['fingerprints', 'templates', 'fingerprint.schema.yaml'];

for (const asset of ASSETS) {
  fs.cpSync(path.join(SRC_DIR, asset), path.join(DEST_DIR, asset), { recursive: true });
}

console.log(`[copy-discovery-assets] copied ${ASSETS.join(', ')} into dist/services/logDiscovery`);
