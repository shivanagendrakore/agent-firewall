/**
 * The options a curl or wget command may carry when it gets a vault value (docs/vault.md, "The option
 * allowlist"). Pure. A command that carries a `vault://` reference is substituted only when every option is
 * on this short list; anything else is refused (FW-VAULT-OPTION) naming the option. The list keeps three
 * promises: the value travels only in a request to the URL's host (no redirects, proxies, resolve or
 * connect-to overrides, no URL read from a file), it is never written to disk or to the output by curl or
 * wget themselves (no trace, verbose, config, write-out variables that echo the request, or file names built
 * from a URL that carries it), and the URLs are written out so the host can be checked against the binding.
 */

import { findRefs } from "./vault-ref.js";
import { own } from "../own.js";

export type Sender = "curl" | "wget";

/** One URL the command requests: its scheme and host as curl or wget will use them. */
export interface SenderUrl {
  text: string;
  scheme: "http" | "https";
  /** Lower case, without brackets or a trailing dot. */
  host: string;
  /** A reference is in the URL itself (or in data that -G moves into it). */
  hasRef: boolean;
}

export type OptionCheck = { ok: true; urls: SenderUrl[] } | { ok: false; option: string; why: string };

interface Spec {
  /** Takes a value (the rest of a short cluster, the next word, or --name=value for wget). */
  arg: boolean;
  /** The value may carry a reference (headers, data, credentials). */
  refOk?: boolean;
  /** Why this value is refused, or null. */
  check?: (value: string) => string | null;
  kind?: "url" | "output" | "remote-name" | "data" | "get" | "wget-output";
}

const METHOD = (v: string): string | null => (/^[A-Za-z]{1,16}$/.test(v) ? null : "a method is a single word of letters");
const NUMBER = (v: string): string | null => (/^\d{1,6}(?:\.\d{1,3})?$/.test(v) ? null : "it takes a number");
const INTEGER = (v: string): string | null => (/^\d{1,4}$/.test(v) ? null : "it takes a whole number");
const NOT_FILE = (v: string): string | null => (v.startsWith("@") && findRefs(v).length > 0 ? "a reference after @ would be read as a file name and printed in curl's error" : null);

/** curl -w variables that report on the transfer, never on what was sent (no %{url}, %{json}, %{header_json}). */
export const WRITE_OUT_VARS: ReadonlySet<string> = new Set([
  "http_code", "response_code", "http_version", "http_connect", "time_total", "time_namelookup", "time_connect", "time_appconnect", "time_pretransfer", "time_starttransfer", "time_redirect", "time_queue", "size_download", "size_upload", "size_header", "size_request", "speed_download", "speed_upload", "content_type", "num_redirects", "num_connects", "num_headers", "num_retries", "remote_ip", "remote_port", "scheme", "exitcode", "stdout", "stderr", "method",
]);

/** Why a curl --write-out format is refused, or null: only %{known} variables, %%, and literal text. */
export function writeOutProblem(format: string): string | null {
  if (format.startsWith("@")) return "-w @file reads its format from a file";
  for (let i = 0; i < format.length; i++) {
    if (format[i] !== "%") continue;
    if (format[i + 1] === "%") {
      i++;
      continue;
    }
    const m = /^%\{([a-z_]+)\}/.exec(format.slice(i));
    if (m === null) return `-w ${format.slice(i, i + 12)}… is not a fixed transfer variable (only %{name} from the documented list; never %output{}, %header{} or %{json})`;
    if (!WRITE_OUT_VARS.has(m[1] as string)) return `-w %{${m[1] as string}} is not on the list of write-out variables that cannot show the request`;
    i += m[0].length - 1;
  }
  return null;
}

const CURL_LONG: Record<string, Spec> = {
  "--silent": { arg: false },
  "--show-error": { arg: false },
  "--fail": { arg: false },
  "--fail-with-body": { arg: false },
  "--include": { arg: false },
  "--show-headers": { arg: false },
  "--head": { arg: false },
  "--get": { arg: false, kind: "get" },
  "--compressed": { arg: false },
  "--no-progress-meter": { arg: false },
  "--request": { arg: true, check: METHOD },
  "--header": { arg: true, refOk: true, check: (v) => (v.startsWith("@") ? "-H @file reads headers from a file" : null) },
  "--data": { arg: true, refOk: true, check: NOT_FILE, kind: "data" },
  "--data-raw": { arg: true, refOk: true, kind: "data" },
  "--data-binary": { arg: true, refOk: true, check: NOT_FILE, kind: "data" },
  "--data-ascii": { arg: true, refOk: true, check: NOT_FILE, kind: "data" },
  "--data-urlencode": { arg: true, refOk: true, check: (v) => (findRefs(v).length > 0 && /^[^=]*@/.test(v) ? "a reference after @ would be read as a file name" : null), kind: "data" },
  "--json": { arg: true, refOk: true, check: NOT_FILE, kind: "data" },
  "--user": { arg: true, refOk: true },
  "--user-agent": { arg: true },
  "--max-time": { arg: true, check: NUMBER },
  "--connect-timeout": { arg: true, check: NUMBER },
  "--retry": { arg: true, check: INTEGER },
  "--output": { arg: true, kind: "output" },
  "--remote-name": { arg: false, kind: "remote-name" },
  "--write-out": { arg: true, check: writeOutProblem },
  "--url": { arg: true, refOk: true, kind: "url" },
};
const CURL_SHORT: Record<string, string> = { s: "--silent", S: "--show-error", f: "--fail", i: "--include", I: "--head", G: "--get", X: "--request", H: "--header", d: "--data", u: "--user", A: "--user-agent", m: "--max-time", o: "--output", O: "--remote-name", w: "--write-out" };

const WGET_LONG: Record<string, Spec> = {
  "--quiet": { arg: false },
  "--no-verbose": { arg: false },
  "--server-response": { arg: false },
  "--content-on-error": { arg: false },
  "--no-config": { arg: false },
  "--output-document": { arg: true, kind: "wget-output" },
  "--header": { arg: true, refOk: true },
  "--method": { arg: true, check: METHOD },
  "--post-data": { arg: true, refOk: true },
  "--body-data": { arg: true, refOk: true },
  "--user": { arg: true, refOk: true },
  "--password": { arg: true, refOk: true },
  "--http-user": { arg: true, refOk: true },
  "--http-password": { arg: true, refOk: true },
  "--user-agent": { arg: true },
  "--timeout": { arg: true, check: NUMBER },
  "--tries": { arg: true, check: INTEGER },
  "--max-redirect": { arg: true, check: (v) => (v === "0" ? null : "wget may not follow redirects with a value (only --max-redirect=0)") },
};
const WGET_SHORT: Record<string, string> = { q: "--quiet", S: "--server-response", O: "--output-document", U: "--user-agent", T: "--timeout", t: "--tries" };

/** Options refused with a reason of their own (the rest: "not on the allowlist"). */
const SPECIAL: Record<string, string> = {
  "curl --location": "curl -L follows redirects to hosts the firewall never checked, and resends custom headers there",
  "curl --location-trusted": "it sends credentials to every host a redirect names",
  "curl --resolve": "it changes which address the bound host name resolves to",
  "curl --connect-to": "it sends the request for the bound host to another host",
  "curl --proxy": "it routes the request through another host",
  "curl --preproxy": "it routes the request through another host",
  "curl --doh-url": "it changes name resolution",
  "curl --dns-servers": "it changes name resolution",
  "curl --unix-socket": "it sends the request to a local socket instead of the host",
  "curl --abstract-unix-socket": "it sends the request to a local socket instead of the host",
  "curl --interface": "it changes how the request is routed",
  "curl --verbose": "it prints the request's headers, the value included",
  "curl --trace": "it writes the request, the value included, to a file or the output",
  "curl --trace-ascii": "it writes the request, the value included, to a file or the output",
  "curl --config": "it reads more options from a file",
  "curl --variable": "it imports environment variables and files into the command",
  "curl --insecure": "it accepts any certificate, so another host can pose as the bound one",
  "curl --next": "it starts another transfer whose options the firewall did not check",
  "wget --input-file": "wget -i reads the URLs to request from a file, so the destination is not on the command line",
  "wget --execute": "it runs a configuration command",
  "wget --debug": "it prints the request's headers, the value included",
  "wget --no-check-certificate": "it accepts any certificate, so another host can pose as the bound one",
  "wget --recursive": "it follows links to hosts the firewall never checked",
  "wget --mirror": "it follows links to hosts the firewall never checked",
};
const CURL_SHORT_SPECIAL: Record<string, string> = { L: "--location", x: "--proxy", v: "--verbose", K: "--config", k: "--insecure", ":": "--next" };
const WGET_SHORT_SPECIAL: Record<string, string> = { i: "--input-file", e: "--execute", d: "--debug", r: "--recursive", m: "--mirror" };

const URL_RE = /^(https?):\/\/(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.?)(?::\d{1,5})?(?:[/?#][^\s\\]*)?$/i;

/** A URL the vault accepts as a destination: an explicit http(s) scheme, a plain host, no user info. */
export function parseSenderUrl(text: string): Omit<SenderUrl, "hasRef"> | null {
  const m = URL_RE.exec(text);
  if (m === null) return null;
  const host = (m[2] as string).toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (host === "") return null;
  return { text, scheme: (m[1] as string).toLowerCase() as "http" | "https", host };
}

const refuse = (program: Sender, option: string, why?: string): OptionCheck => ({ ok: false, option, why: why ?? SPECIAL[`${program} ${option}`] ?? "it is not on the vault's option allowlist" });

/**
 * Checks every word after the program against the allowlist. Words are literal (the caller has refused
 * variables and substitutions). On success, the URLs the command requests.
 */
export function checkSenderArgs(program: Sender, words: readonly string[]): OptionCheck {
  const LONG = program === "curl" ? CURL_LONG : WGET_LONG;
  const SHORT = program === "curl" ? CURL_SHORT : WGET_SHORT;
  const SHORT_SPECIAL = program === "curl" ? CURL_SHORT_SPECIAL : WGET_SHORT_SPECIAL;
  const urlWords: string[] = [];
  const seen: { name: string; spec: Spec; value: string | null; shown: string }[] = [];
  let ended = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (ended || !w.startsWith("-") || w === "-") {
      if (w === "-") return refuse(program, "-", "a lone - is not a URL");
      urlWords.push(w);
      continue;
    }
    if (w === "--") {
      ended = true;
      continue;
    }
    const take = (name: string, spec: Spec, shown: string, attached: string | null): OptionCheck | null => {
      let value: string | null = null;
      if (spec.arg) {
        if (attached !== null) value = attached;
        else {
          if (i + 1 >= words.length) return refuse(program, shown, "it needs a value");
          value = words[++i] as string;
        }
      } else if (attached !== null) return refuse(program, shown, "it takes no value");
      seen.push({ name, spec, value, shown });
      return null;
    };
    if (w.startsWith("--")) {
      const eq = w.indexOf("=");
      const name = eq === -1 ? w : w.slice(0, eq);
      // curl takes no --name=value; wget does (GNU getopt). Abbreviations are refused: only full names.
      if (program === "curl" && eq !== -1) return refuse(program, name, "curl has no --name=value form; write the value as the next word");
      const spec = own(LONG, name);
      if (spec === undefined) return refuse(program, name);
      const r = take(name, spec, name, eq === -1 ? null : w.slice(eq + 1));
      if (r !== null) return r;
      continue;
    }
    if (program === "wget" && w === "-nv") {
      seen.push({ name: "--no-verbose", spec: { arg: false }, value: null, shown: "-nv" });
      continue;
    }
    // A short cluster (-sSf, -XPOST, -qO-): it stops at the first letter that takes a value.
    for (let j = 1; j < w.length; j++) {
      const ch = w[j] as string;
      const long = own(SHORT, ch);
      if (long === undefined) {
        const special = own(SHORT_SPECIAL, ch);
        return refuse(program, `-${ch}`, special !== undefined ? SPECIAL[`${program} ${special}`] : undefined);
      }
      const spec = own(LONG, long) as Spec;
      const rest = w.slice(j + 1);
      const r = take(long, spec, `-${ch}`, spec.arg && rest !== "" ? rest : null);
      if (r !== null) return r;
      if (spec.arg) break;
    }
  }
  for (const s of seen) {
    if (s.value === null) continue;
    if (!s.spec.refOk && findRefs(s.value).length > 0) return refuse(program, s.shown, `a vault reference may only be in a header, the data, the credentials or the URL, not in ${s.shown}`);
    const bad = s.spec.check?.(s.value) ?? null;
    if (bad !== null) return refuse(program, s.shown, bad);
    if (s.spec.kind === "url") urlWords.push(s.value);
  }
  if (urlWords.length === 0) return refuse(program, "(no URL)", "the command names no URL, so its destination cannot be checked");
  const dataRef = seen.some((s) => s.spec.kind === "data" && s.value !== null && findRefs(s.value).length > 0);
  const get = seen.some((s) => s.spec.kind === "get");
  const urls: SenderUrl[] = [];
  for (const u of urlWords) {
    const p = parseSenderUrl(u);
    if (p === null) return refuse(program, u.slice(0, 80), "a URL must be written out as http:// or https:// with a plain host (no user info, no globbing in the host, no backslash)");
    urls.push({ ...p, hasRef: findRefs(u).length > 0 || (get && dataRef) });
  }
  // VG5: a response saved to a file is not filtered like stdout is, and a server that echoes the request
  // (a debugging endpoint) would write the value into a file the person's tools read later. With any
  // reference in the command, saving to a file is refused, and so is plain wget (which saves one named after
  // the URL); `-o -` / `wget -O -` (stdout), `-o /dev/null` and a shell redirection (which run's output filter
  // covers) still work.
  if (words.some((w) => findRefs(w).length > 0)) {
    const save = seen.find((s) => ((s.spec.kind === "output" || s.spec.kind === "wget-output") && s.value !== "-" && s.value !== "/dev/null") || s.spec.kind === "remote-name");
    if (save !== undefined) return refuse(program, save.shown, `${save.shown} saves the response to a file, unfiltered, in a command that carries a vault reference (a server that echoes the request would write the value there); print it to stdout and redirect in the shell instead`);
    // Plain wget saves the response to a file named after the URL: the same file write as -O FILE.
    if (program === "wget" && !seen.some((s) => s.spec.kind === "wget-output")) return refuse(program, "(no -O)", "without -O, wget saves the response to a file named after the URL, unfiltered, in a command that carries a vault reference; add -O - (stdout) and redirect in the shell instead");
  }
  const refInUrl = urls.some((u) => u.hasRef);
  if (refInUrl) {
    const out = seen.find((s) => s.spec.kind === "output" || s.spec.kind === "remote-name");
    if (out !== undefined) return refuse(program, out.shown, `${out.shown} with a reference in the URL could name the file after it (curl's #1 and -O take parts of the URL)`);
  }
  return { ok: true, urls };
}

/** Prefix assignments a sending command may carry: none that can change routing, name resolution, trust or what runs. */
export const SAFE_ASSIGN = /^(?:LANG|LANGUAGE|LC_[A-Z]+|TZ|NO_COLOR|TERM|COLUMNS)$/;

/** Local destinations: loopback, unspecified, link-local and the .localhost names. */
export function isLocalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h) || /^0+(?:\.0+){0,3}$/.test(h) || /^169\.254\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^\d+$/.test(h) || /^0x[0-9a-f]+$/i.test(h)) return true; // 2130706433, 0x7f000001: numeric forms curl accepts
  if (h.includes(":")) {
    const v6 = h.replace(/^0*:/, ":");
    return v6 === "::" || v6 === "::1" || /^(?:0{1,4}:){7}0{0,3}1$/.test(h) || /^fe[89ab][0-9a-f]?:/i.test(h) || /^::ffff:(?:127\.|0\.|169\.254\.)/i.test(h);
  }
  return false;
}
