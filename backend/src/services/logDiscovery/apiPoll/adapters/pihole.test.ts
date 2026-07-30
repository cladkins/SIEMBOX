import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mapRow } from './pihole';

test('mapRow matches pihole-query.parser.json\'s expected "query[TYPE] domain from client" format', () => {
  const row = [1705320000, 'A', 'tracker.example.com', '203.0.113.5', 2];
  const mapped = mapRow(row);
  assert.ok(mapped);
  assert.equal(mapped!.message, 'query[A] tracker.example.com from 203.0.113.5');
  assert.equal(mapped!.timestamp?.toISOString(), '2024-01-15T12:00:00.000Z');
});

test('mapRow synthesizes a stable eventId for the same row, different for a different one', () => {
  const rowA = [1705320000, 'A', 'tracker.example.com', '203.0.113.5', 2];
  const rowB = [1705320000, 'A', 'tracker.example.com', '203.0.113.5', 2];
  const rowC = [1705320001, 'AAAA', 'cdn.example.net', '198.51.100.9', 2];
  assert.equal(mapRow(rowA)!.eventId, mapRow(rowB)!.eventId);
  assert.notEqual(mapRow(rowA)!.eventId, mapRow(rowC)!.eventId);
});

test('mapRow returns null for a non-numeric timestamp', () => {
  assert.equal(mapRow(['not-a-timestamp', 'A', 'example.com', '203.0.113.5']), null);
});
