/**
 * v0.3 `run`: the server name (SNI) in a TLS ClientHello, pure. The run's
 * proxy reads the first bytes a client sends through a CONNECT tunnel and
 * refuses the tunnel when TLS names a different server than the CONNECT line
 * (a client that tunnels to an admitted host and then asks a CDN for another
 * site). The proxy never decrypts anything; the ClientHello is plain text.
 */

export type SniResult =
  /** More bytes are needed to decide. */
  | { state: "need-more" }
  /** The bytes are not a TLS handshake (or are malformed). */
  | { state: "not-tls"; why: string }
  /** A complete ClientHello; sni is null when it names no server. */
  | { state: "tls"; sni: string | null }
  /** A ClientHello whose server name cannot be trusted (two names, an encrypted ClientHello): refused on every port. */
  | { state: "refused"; why: string };

/** Above this much buffered handshake the client is not sending an ordinary ClientHello. */
export const MAX_CLIENT_HELLO = 65536;

export function parseClientHello(buf: Uint8Array): SniResult {
  if (buf.length === 0) return { state: "need-more" };
  if (buf[0] !== 0x16) return { state: "not-tls", why: "the first byte is not a TLS handshake record" };
  // Collect the handshake payload across records (a ClientHello may be split over several).
  const payload: number[] = [];
  let off = 0;
  let hsLen = -1;
  while (true) {
    if (buf.length < off + 5) return buf.length > MAX_CLIENT_HELLO ? { state: "not-tls", why: "the ClientHello is too large" } : { state: "need-more" };
    if (buf[off] !== 0x16) return { state: "not-tls", why: "a non-handshake record arrived before the ClientHello was complete" };
    if (buf[off + 1] !== 0x03) return { state: "not-tls", why: "unknown record version" };
    const len = ((buf[off + 3] as number) << 8) | (buf[off + 4] as number);
    if (len === 0 || len > 18432) return { state: "not-tls", why: "bad record length" };
    if (buf.length < off + 5 + len) return { state: "need-more" };
    for (let i = 0; i < len; i++) payload.push(buf[off + 5 + i] as number);
    off += 5 + len;
    if (hsLen === -1 && payload.length >= 4) {
      if (payload[0] !== 0x01) return { state: "not-tls", why: "the first handshake message is not a ClientHello" };
      hsLen = ((payload[1] as number) << 16) | ((payload[2] as number) << 8) | (payload[3] as number);
      if (hsLen > MAX_CLIENT_HELLO) return { state: "not-tls", why: "the ClientHello is too large" };
    }
    if (hsLen !== -1 && payload.length >= 4 + hsLen) break;
    if (off > MAX_CLIENT_HELLO) return { state: "not-tls", why: "the ClientHello is too large" };
  }
  return sniFrom(payload.slice(4, 4 + hsLen));
}

function sniFrom(h: number[]): SniResult {
  let p = 2 + 32; // client_version, random
  const bad = (why: string): SniResult => ({ state: "not-tls", why });
  const u8 = (): number => h[p++] as number;
  const u16 = (): number => ((h[p++] as number) << 8) | (h[p++] as number);
  if (h.length < p + 1) return bad("truncated ClientHello");
  p += 1 + (h[p] as number); // session id
  if (h.length < p + 2) return bad("truncated ClientHello");
  p += 2 + (((h[p] as number) << 8) | (h[p + 1] as number)); // cipher suites
  if (h.length < p + 1) return bad("truncated ClientHello");
  p += 1 + (h[p] as number); // compression methods
  if (p === h.length) return { state: "tls", sni: null }; // no extensions at all
  if (h.length < p + 2) return bad("truncated ClientHello");
  const extEnd = p + 2 + (((h[p] as number) << 8) | (h[p + 1] as number));
  p += 2;
  if (extEnd > h.length) return bad("truncated extensions");
  // Every extension is read (not only up to the first server_name): a second server_name, or an encrypted
  // ClientHello that names the real server only inside the encryption, would make the checked name a decoy.
  let sni: string | null = null;
  let sawName = false;
  const seen = new Set<number>();
  while (p + 4 <= extEnd) {
    const type = u16();
    const len = u16();
    const end = p + len;
    if (end > extEnd) return bad("truncated extension");
    if (seen.has(type)) return { state: "refused", why: type === 0x0000 ? "the ClientHello carries two server_name extensions" : `the ClientHello repeats extension ${type}` };
    seen.add(type);
    if (HIDDEN_NAME_EXTENSIONS.has(type)) return { state: "refused", why: `the ClientHello is encrypted (${HIDDEN_NAME_EXTENSIONS.get(type) as string}): the server it asks for is hidden from the check` };
    if (type === 0x0000) {
      if (len < 2) return bad("empty server_name extension");
      const listEnd = p + 2 + u16();
      if (listEnd > end) return bad("bad server_name list");
      while (p + 3 <= listEnd) {
        const kind = u8();
        const nlen = u16();
        if (p + nlen > listEnd) return bad("bad server name");
        const name = String.fromCharCode(...h.slice(p, p + nlen));
        p += nlen;
        if (kind !== 0) continue;
        if (sawName) return { state: "refused", why: "the server_name extension names two servers" };
        sawName = true;
        if (!/^[\x21-\x7e]+$/.test(name)) return bad("a server name with unprintable characters");
        sni = name.toLowerCase().replace(/\.$/, "");
      }
    }
    p = end;
  }
  return { state: "tls", sni };
}

/**
 * Extensions that hide the real server name from anyone between client and server: Encrypted Client Hello
 * (0xfe0d, RFC 9849) carries the inner ClientHello, with the name the client really wants, encrypted; the
 * outer server_name is then only the provider's public name. The draft ESNI extension (0xffce) is the same idea.
 * The proxy cannot check a name it cannot read, so it refuses the tunnel.
 */
export const HIDDEN_NAME_EXTENSIONS: ReadonlyMap<number, string> = new Map([
  [0xfe0d, "Encrypted Client Hello"],
  [0xffce, "encrypted SNI"],
]);

/**
 * A minimal ClientHello naming `sni` (or none), for tests and the doctor probe. `extra` adds raw extensions
 * after it (type and body), for the tests of what the proxy refuses.
 */
export function buildClientHello(sni: string | null, extra: readonly { type: number; body: readonly number[] }[] = []): Buffer {
  const ext: number[] = [];
  if (sni !== null) {
    const name = [...Buffer.from(sni, "ascii")];
    const entry = [0, name.length >> 8, name.length & 255, ...name];
    const list = [entry.length >> 8, entry.length & 255, ...entry];
    ext.push(0, 0, list.length >> 8, list.length & 255, ...list);
  }
  for (const x of extra) ext.push(x.type >> 8, x.type & 255, x.body.length >> 8, x.body.length & 255, ...x.body);
  const body = [0x03, 0x03, ...new Array<number>(32).fill(7), 0, 0, 2, 0x13, 0x01, 1, 0, ext.length >> 8, ext.length & 255, ...ext];
  const hs = [0x01, (body.length >> 16) & 255, (body.length >> 8) & 255, body.length & 255, ...body];
  return Buffer.from([0x16, 0x03, 0x01, hs.length >> 8, hs.length & 255, ...hs]);
}
