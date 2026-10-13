/**
 * YAML for the backend. Load and dump YAML through this module, not js-yaml
 * directly, so the parser is chosen in one place.
 *
 * It is js-yaml 4, on its maintained 4.x line (npm dist-tag v4-legacy; 4.3 adds
 * the maxTotalMergeKeys cap on `<<` merge work). Everything SIEMBox reads as
 * YAML (rules/ and the detection catalog, rules and Sigma pasted into the UI,
 * Nuclei templates, discovery fingerprints) was written against js-yaml 4, and
 * the frontend's YAML check runs js-yaml 4 too. js-yaml 5 loads some of it
 * differently, and no schema or option turns these off:
 *  - a quoted string or flow collection whose continuation line is indented no
 *    deeper than its key, or a tab before or inside a flow collection
 *    (`key:<TAB>[x]`, `-<TAB>[x]`, `[a,<TAB>b]`), is a "deficient indentation"
 *    error, so rules stored that way could no longer be saved;
 *  - an empty list entry (`-`) followed by a less-indented entry closes the
 *    inner list, which silently regroups a Sigma selection;
 *  - block content on a `---` line, and a key after `<<` that repeats a merged
 *    non-string key, are errors.
 * Its load() also defaults to the bare YAML 1.2 core schema (no `<<`,
 * timestamps, !!binary, !!omap or !!pairs), throws on an empty stream, and
 * resolves some number and date spellings differently. yaml.test.ts pins the
 * js-yaml 4 behaviour each of these relies on.
 */
export { load, loadAll, dump, YAMLException } from 'js-yaml';
