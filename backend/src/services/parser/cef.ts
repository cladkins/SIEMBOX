/**
 * Parse a CEF extension string ("key=value key=value ...") into a map.
 *
 * CEF extension values may contain spaces, so a value runs until the next
 * " key=" token or the end of the string. Keys are alphanumeric — both the CEF
 * standard keys (src, dst, spt, dpt, act, msg, ...) and vendor keys such as
 * UNIFIipsSignature or UNIFIpolicyType.
 *
 * Example:
 *   "src=5.61.209.43 dst=192.168.1.194 act=blocked msg=intrusion blocked"
 *   => { src: "5.61.209.43", dst: "192.168.1.194", act: "blocked", msg: "intrusion blocked" }
 */
export function parseCefExtension(ext: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!ext) return out;

  // Locate each "key=" token (a key at the start or after whitespace); the value
  // for a key is the text up to the next token's key, computed by slicing. This
  // is linear — the previous one-regex approach used a lazy quantifier with a
  // look-ahead, which backtracks polynomially on adversarial input (ReDoS).
  const keyRe = /(^|\s)([A-Za-z][\w.]*)=/g;
  const tokens: Array<{ key: string; keyStart: number; valStart: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = keyRe.exec(ext)) !== null) {
    tokens.push({ key: m[2], keyStart: m.index + m[1].length, valStart: keyRe.lastIndex });
  }
  for (let i = 0; i < tokens.length; i++) {
    const end = i + 1 < tokens.length ? tokens[i + 1].keyStart : ext.length;
    const value = ext.slice(tokens[i].valStart, end).trim();
    if (value.length > 0) out[tokens[i].key] = value;
  }
  return out;
}
