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

  const re = /([A-Za-z][\w.]*)=(.*?)(?=\s+[A-Za-z][\w.]*=|$)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(ext)) !== null) {
    const value = m[2].trim();
    if (value.length > 0) out[m[1]] = value;
  }
  return out;
}
