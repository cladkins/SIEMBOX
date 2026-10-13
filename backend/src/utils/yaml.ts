/**
 * YAML for the backend: js-yaml 5, loading documents the way js-yaml 4 did.
 *
 * Everything SIEMBox reads as YAML (rules/ and the detection catalog, rules and
 * Sigma pasted into the UI, Nuclei templates, discovery fingerprints) was
 * written against js-yaml 4. js-yaml 5's `load()` defaults to the bare YAML 1.2
 * core schema, where js-yaml 4's default schema also resolved `<<` merge keys
 * and unquoted timestamps (to Date), read the !!binary, !!omap and !!pairs
 * tags, and stringified collection mapping keys (`? [a, b]`); LOAD_SCHEMA adds
 * those back. js-yaml 5 also finds no document in a stream that holds only
 * comments or blank lines (js-yaml 4 found one empty, null document), and its
 * `load()` throws on a stream with no document (js-yaml 4 returned undefined);
 * `load()` and `loadAll()` below return what js-yaml 4 did. Load YAML through
 * this module, not js-yaml directly.
 *
 * Still different from js-yaml 4, on input none of the shipped content uses:
 *  - numbers follow YAML 1.2 core resolution: `0b101`, `-0x1F` and `+0o17` stay
 *    strings, `-.5` and `+.5` are numbers, and `-0` is -0;
 *  - impossible dates and times (`2024-02-30`, `25:00:00`) stay strings rather
 *    than rolling over, and years 0000-0099 are no longer read as 19xx;
 *  - !!set throws (js-yaml 5 would build a Set; js-yaml 4 built an object);
 *  - a tab right after `[`, `{`, `,` or `:` in a flow collection nested under a
 *    block key (`a: [1,<TAB>2]`) is a syntax error;
 *  - one load merges at most 10,000 keys through `<<` (maxTotalMergeKeys);
 *  - a few inputs js-yaml 4 rejected now load (an empty key, `!!null ""`), and
 *    error messages are worded differently.
 *
 * `dump` is js-yaml's own: its default schema quotes any string a YAML 1.1 or
 * 1.2 reader could mistake for another type.
 */
import {
  loadAll as loadDocuments,
  CORE_SCHEMA,
  mergeTag,
  timestampTag,
  binaryTag,
  omapTag,
  pairsTag,
  legacyMapTag,
  YAMLException,
} from 'js-yaml';

export { dump } from 'js-yaml';

const LOAD_SCHEMA = CORE_SCHEMA.withTags(mergeTag, timestampTag, binaryTag, omapTag, pairsTag, legacyMapTag);

// Input js-yaml 4 read as no document at all: blank (spaces, after an optional
// BOM) up to at most one line break. Any other input without content, such as
// only comments or several blank lines, was one empty (null) document.
const NO_DOCUMENT = /^\uFEFF?[ ]*[\r\n]?$/;

/** Parse a YAML stream that may hold several `---`-separated documents. */
export function loadAll(input: string): unknown[] {
  const documents = loadDocuments(input, { schema: LOAD_SCHEMA });
  return documents.length === 0 && !NO_DOCUMENT.test(input) ? [null] : documents;
}

/** Parse a single-document YAML string: undefined when it holds no document. Throws on invalid YAML. */
export function load(input: string): unknown {
  const documents = loadAll(input);
  if (documents.length > 1) throw new YAMLException('expected a single document in the stream, but found more');
  return documents[0];
}
