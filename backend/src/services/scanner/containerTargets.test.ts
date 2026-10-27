/** "All discovered images" for scheduled container scans. Run with `npm test`. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scannableImageRefs } from './containerTargets';

const img = (image: string, scannable = true) => ({ image, image_id: '', containers: [], running: 1, scannable });

test('scannable images from the SIEMBox host and every shipper, deduplicated, host first', () => {
  const r = scannableImageRefs(
    { images: [img('nginx:latest'), img('sha256:abc', false)] },
    [{ images: [img('nginx:latest'), img('ghcr.io/x/app:1.2')] }, { images: [img(' postgres:16 '), img('local-build', false)] }]
  );
  assert.deepEqual(r, { images: ['nginx:latest', 'ghcr.io/x/app:1.2', 'postgres:16'], dropped: 0 });
});

test('nothing discovered (no socket, no shippers) is an empty list', () => {
  assert.deepEqual(scannableImageRefs({ images: [] }, []), { images: [], dropped: 0 });
});

test('capped, with the overflow counted', () => {
  const many = Array.from({ length: 5 }, (_, i) => img(`repo/app${i}:1`));
  assert.deepEqual(scannableImageRefs({ images: many }, [], 3), { images: ['repo/app0:1', 'repo/app1:1', 'repo/app2:1'], dropped: 2 });
});
