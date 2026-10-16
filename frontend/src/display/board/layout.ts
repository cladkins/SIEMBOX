/**
 * The grid for one view (BIG-DISPLAY.md §5.2). Pure.
 *
 * Landscape: 1 → 1×1, 2 → 2×1, 3 → 3×1, 4 → 2×2, 5–6 → 3×2. Portrait: one
 * column up to 3 panels, two beyond. With 4 panels or fewer the threat map
 * spans two columns and is placed first. Panels are placed in order, row by row; the last panel
 * of a row that would leave a gap is stretched to fill it, so the grid never
 * shows a hole.
 */

export interface GridLayout {
  columns: number;
  rows: number;
  /** The panel keys in placement order (a wide map goes first). */
  keys: string[];
  /** Column span of each panel, in that order. */
  spans: number[];
}

export function isMapKey(key: string): boolean {
  return key === 'threat_map' || key.startsWith('threat_map:');
}

export function gridLayout(panelKeys: readonly string[], portrait: boolean): GridLayout {
  const n = panelKeys.length;
  if (n === 0) return { columns: 1, rows: 1, keys: [], spans: [] };
  let columns: number;
  if (portrait) columns = n <= 3 ? 1 : 2;
  else columns = n <= 3 ? n : n === 4 ? 2 : 3;

  const wide = n > 1 && n <= 4 && panelKeys.some(isMapKey);
  // A wide map leads, so the others fill the rows below or beside it.
  const keys = wide ? [...panelKeys.filter(isMapKey), ...panelKeys.filter((k) => !isMapKey(k))] : [...panelKeys];
  // Room for the wide map: 2 panels → 3 columns, 3 → 2 (map on its own row), 4 → 3.
  if (wide && !portrait) columns = n === 3 ? 2 : 3;
  const spans = keys.map((key) => (wide && columns >= 2 && isMapKey(key) ? 2 : 1));

  // Pack row by row, stretching a row's last panel over any gap.
  let rows = 0;
  let used = columns; // forces a new row on the first panel
  let lastInRow = -1;
  spans.forEach((span, i) => {
    if (used + span > columns) {
      if (lastInRow >= 0) spans[lastInRow] += columns - used;
      rows += 1;
      used = 0;
    }
    used += span;
    lastInRow = i;
  });
  if (lastInRow >= 0) spans[lastInRow] += columns - used;
  return { columns, rows, keys, spans };
}

/**
 * The map's fill for a normalised count t in [0, 1] (0 = no alerts): a
 * neutral lightness ramp where more alerts means brighter, clamped so one
 * alert is visibly lighter than none (§5.1). Zero is the darkest country, so
 * an empty map is quiet on a dark screen.
 */
export function mapFill(t: number): string {
  if (!(t > 0)) return 'hsl(212, 18%, 17%)';
  const lightness = 32 + 50 * Math.sqrt(Math.min(1, t));
  return `hsl(212, 22%, ${lightness.toFixed(1)}%)`;
}
