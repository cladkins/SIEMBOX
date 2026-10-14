/**
 * ES2022 built-ins that libraries we ship call, but that some browsers in
 * vite.config.ts's build.target (Chrome 87, Firefox 78, Safari 14, Edge 88)
 * lack. Vite lowers syntax to that target but never adds missing built-ins.
 *
 * - Array.prototype.at (Chrome 92, Firefox 90, Safari 15.4): marked 18's lexer
 *   calls it on every parse, so without it AI Analyst and triage markdown
 *   would fail to render there. marked 12 did not use it.
 * - Object.hasOwn (Chrome 93, Firefox 92, Safari 15.4): marked 18 (reference
 *   links) and Pinia 4 (`$patch` with an object, hydration).
 *
 * main.ts imports this first; the libraries only call these at run time, never
 * while their modules load. Each is defined only where missing, with the
 * built-in's results for arrays and its property attributes (writable,
 * configurable, not enumerable).
 */
function define(target: object, name: string, value: (...args: never[]) => unknown) {
  if (!(name in target)) {
    Object.defineProperty(target, name, { value, writable: true, configurable: true });
  }
}

define(Array.prototype, 'at', function at(this: ArrayLike<unknown>, index: number) {
  const o = Object(this) as ArrayLike<unknown>;
  const length = o.length >>> 0;
  const relative = Math.trunc(Number(index)) || 0; // NaN and -0 count as 0
  const k = relative >= 0 ? relative : length + relative;
  return k < 0 || k >= length ? undefined : o[k];
});

define(Object, 'hasOwn', function hasOwn(object: object, key: PropertyKey) {
  // Throws on null and undefined, as Object.hasOwn does.
  return Object.prototype.hasOwnProperty.call(object, key);
});
