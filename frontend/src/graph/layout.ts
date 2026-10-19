/**
 * Where new nodes go (pure): on an arc around the node that was expanded,
 * facing away from the rest of the graph, at the first radius where they
 * don't sit on top of what is already there. Nodes already on the canvas
 * never move; only Re-layout (Cytoscape's concentric layout, by hop
 * distance) rearranges everything.
 */

export interface Point {
  x: number;
  y: number;
}

/** Closest two nodes' centres may be. */
export const MIN_GAP = 46;
const BASE_RADIUS = 130;
const RING_STEP = 70;
const MAX_RINGS = 8;

function centroid(points: Point[]): Point | null {
  if (points.length === 0) return null;
  let x = 0;
  let y = 0;
  for (const p of points) {
    x += p.x;
    y += p.y;
  }
  return { x: x / points.length, y: y / points.length };
}

function clearOf(p: Point, others: Point[], gap: number): boolean {
  for (const o of others) {
    const dx = p.x - o.x;
    const dy = p.y - o.y;
    if (dx * dx + dy * dy < gap * gap) return false;
  }
  return true;
}

/**
 * Positions for `count` new nodes around `anchor`. `existing` are the nodes
 * already placed (the anchor among them). A lone anchor gets a full circle;
 * otherwise the arc (up to 200°, wider when crowded) points away from the
 * centroid of the others.
 */
export function placeAround(anchor: Point, count: number, existing: Point[]): Point[] {
  if (count <= 0) return [];
  const others = existing.filter((p) => p.x !== anchor.x || p.y !== anchor.y);
  const middle = centroid(others);
  const away = middle ? Math.atan2(anchor.y - middle.y, anchor.x - middle.x) : -Math.PI / 2;
  const full = !middle || (Math.abs(anchor.x - middle.x) < 1 && Math.abs(anchor.y - middle.y) < 1);
  let best: Point[] = [];
  let bestClear = -1;
  for (let ring = 0; ring < MAX_RINGS; ring++) {
    const radius = BASE_RADIUS + ring * RING_STEP;
    // Spread so neighbours on the arc are MIN_GAP apart, within the span allowed.
    const needed = ((count - (full ? 0 : 1)) * MIN_GAP) / radius;
    const span = full ? 2 * Math.PI : Math.min(2 * Math.PI, Math.max((200 * Math.PI) / 180, needed));
    const step = count === 1 ? 0 : full || span >= 2 * Math.PI ? span / count : span / (count - 1);
    const start = full || span >= 2 * Math.PI ? away : away - span / 2;
    const points: Point[] = [];
    for (let i = 0; i < count; i++) {
      const angle = start + step * i;
      points.push({ x: Math.round(anchor.x + radius * Math.cos(angle)), y: Math.round(anchor.y + radius * Math.sin(angle)) });
    }
    const clear = points.filter((p) => clearOf(p, others, MIN_GAP)).length;
    if (clear > bestClear) {
      best = points;
      bestClear = clear;
    }
    if (clear === count) break;
  }
  return best;
}
