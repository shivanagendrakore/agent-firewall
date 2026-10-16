/**
 * F-b: inline interpreter code (python -c, node -e, ruby -e, perl -e, php -r,
 * deno/bun eval, and here-documents fed to an interpreter). Code that cannot
 * write, delete, run other programs, reach the network or reflect its way to
 * any of those is judged as a reader of the paths it names. Code that can is
 * judged as in v0.1: every quoted path is probed as a read and as a write. The
 * decision is per language and errs to "can write" whenever the code is not
 * clearly read-only.
 */

import { addEffect, addFinding, egress, readPath, taintFetched, writePath, type Collector } from "../effects.js";

export type Lang = "python" | "node" | "ruby" | "perl" | "php" | "deno" | "bun" | "other";

export interface Capabilities {
  /** File write, delete, rename, chmod, symlink APIs. */
  writes: boolean;
  /** Subprocesses, eval/exec, loading code from a file or a third-party module. */
  executes: boolean;
  network: boolean;
  /** Reflection or decoding that can reach any of the above. */
  dynamic: boolean;
}

export function langOf(interpreter: string): Lang {
  const n = interpreter.replace(/^.*\//, "");
  if (/^(?:python[0-9.]*|pypy[0-9]*)$/.test(n)) return "python";
  if (/^(?:node|nodejs|ts-node|tsx)$/.test(n)) return "node";
  if (n === "ruby" || n === "irb") return "ruby";
  if (n === "perl") return "perl";
  if (n === "php") return "php";
  if (n === "deno") return "deno";
  if (n === "bun") return "bun";
  return "other";
}

/** v0.1's sign that inline code uses the network, other programs or decoding (kept for the opaque effect). */
const OPAQUE_CODE = /\b(?:require\s*\(\s*["'](?:http|https|net|tls|dgram|dns|child_process|fs\/promises|fs)["']\)|import\s+[^;]*\bfrom\s+["'](?:node:)?(?:http|https|net|child_process)["']|socket|urllib|urlopen|requests\.|httpx|http\.client|aiohttp|fetch\s*\(|XMLHttpRequest|WebSocket|net\.|tls\.|dgram|https?\.(?:get|request)|child_process|subprocess|os\.system|os\.popen|os\.exec|pty\.spawn|exec\s*\(|execSync|spawn|eval\s*\(|Function\s*\(|Deno\.(?:run|Command)|Bun\.spawn|system\s*\(|`[^`]*`|IO\.popen|Open3|Net::HTTP|LWP|IO::Socket|curl_exec|fsockopen|shell_exec|passthru|proc_open|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|DownloadString|do shell script|base64|b64decode|atob|fromCharCode|__import__|importlib|compile\s*\(|marshal|pickle\.loads)/;

const NETWORK = /\brequire\s*\(\s*["'](?:node:)?(?:http|https|http2|net|tls|dgram|dns|undici)["']\s*\)|\bfrom\s+["'](?:node:)?(?:http|https|http2|net|tls|dgram|dns)["']|\bsocket\b|\burllib|\burlopen|\brequests\b|\bhttpx\b|\bhttp\.client|\baiohttp|\bftplib|\bsmtplib|\btelnetlib|\bfetch\s*\(|XMLHttpRequest|WebSocket|\bnet\.(?:connect|createConnection|Socket)|\btls\.connect|\bdgram\b|\bhttps?\.(?:get|request)\b|Net::HTTP|\bLWP\b|IO::Socket|HTTP::Tiny|\bcurl_\w+|\bfsockopen|\bstream_socket_client|Deno\.(?:connect|listen)|Bun\.(?:connect|listen|serve)|\bOpen-?URI|\bopen-uri\b|URI\.open/;

const DYNAMIC: Record<Lang, RegExp> = {
  python: /\b(?:getattr|setattr|delattr|__import__|importlib|globals|vars|locals|eval|exec|compile|__builtins__|__dict__|__class__|__subclasses__|base64|b64decode|binascii|unhexlify|codecs\.decode|fromhex|marshal|pickle|ctypes|chr\s*\()/,
  node: /\b(?:Function\s*\(|Reflect\.|globalThis\s*\[|global\s*\[|this\s*\[|eval\s*\(|process\.binding|module\.constructor|vm\.|atob|fromCharCode|Buffer\.from\s*\([^)]*["'](?:base64|hex)["'])|\[\s*["'`][^"'`]*["'`]\s*\+/,
  ruby: /\b(?:send|public_send|__send__|instance_variable_get|instance_variable_set|const_get|instance_eval|class_eval|module_eval|eval|binding|Base64|unpack1?|method\s*\()/,
  perl: /\b(?:eval|no\s+strict|can\s*\(|pack|unpack|MIME::Base64|decode_base64)\b|&\{|&\$|\$\{\s*["']/,
  php: /\b(?:call_user_func\w*|create_function|eval|assert|base64_decode|hex2bin|str_rot13|gzinflate|gzuncompress|ReflectionFunction|ReflectionClass)\b|\$\$\w|\$\w+\s*\(/,
  deno: /\b(?:Function\s*\(|Reflect\.|globalThis\s*\[|eval\s*\(|atob|fromCharCode)/,
  bun: /\b(?:Function\s*\(|Reflect\.|globalThis\s*\[|eval\s*\(|atob|fromCharCode)/,
  other: /./,
};

const STRING_BUILT_NAME = /\[\s*["'][^"'\]]*["']\s*\+|\+\s*["'][^"']*["']\s*\]/;

const PY_READ_MODULES = new Set(["json", "sys", "os", "os.path", "shutil", "pathlib", "tomllib", "tomli", "yaml", "csv", "re", "glob", "collections", "itertools", "functools", "pprint", "textwrap", "datetime", "time", "math", "statistics", "string", "configparser", "hashlib", "ast", "typing", "dataclasses", "enum", "fnmatch", "platform", "locale", "io", "struct", "shlex", "unicodedata", "difflib", "plistlib", "xml", "xml.etree", "xml.etree.ElementTree", "html", "decimal", "fractions", "random", "uuid", "operator", "keyword", "numbers", "copy", "bisect", "heapq", "array", "calendar", "email.utils", "urllib.parse", "importlib.metadata"]);
const NODE_READ_MODULES = new Set(["fs", "fs/promises", "path", "os", "util", "url", "crypto", "assert", "buffer", "events", "string_decoder", "querystring", "readline", "process", "console"]);
const RUBY_READ_LIBS = new Set(["json", "yaml", "psych", "set", "pp", "time", "date", "csv", "pathname", "digest", "securerandom", "uri", "erb", "toml", "tomlrb"]);
const PERL_READ_MODULES = new Set(["strict", "warnings", "utf8", "JSON", "JSON::PP", "Data::Dumper", "File::Basename", "File::Spec", "List::Util", "Scalar::Util", "POSIX", "Cwd", "Getopt::Long", "Time::HiRes", "Encode"]);

/** The arguments of a call starting at the "(" at index open, split at top-level commas (quotes respected). */
function callArgs(code: string, open: number): string[] {
  const args: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let cur = "";
  for (let i = open + 1; i < code.length && i < open + 2000; i++) {
    const ch = code[i] as string;
    if (quote !== null) {
      cur += ch;
      if (ch === "\\") {
        cur += code[i + 1] ?? "";
        i++;
      } else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) {
        args.push(cur.trim());
        return args;
      }
      depth--;
    }
    if (ch === "," && depth === 0) {
      args.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  args.push(cur.trim());
  return args;
}

const literal = (a: string): string | null => /^(?:[rRbBuUfF]{0,2})(["'])(.*)\1$/s.exec(a)?.[2] ?? null;

/** Python open(): a mode with w, a, x or +, or a mode that is not a literal, writes. */
function pythonOpenWrites(code: string): boolean {
  for (const m of code.matchAll(/(?<![\w.])open\s*\(|\.open\s*\(/g)) {
    const method = m[0].startsWith(".");
    const args = callArgs(code, (m.index ?? 0) + m[0].length - 1);
    const kw = args.find((a) => /^mode\s*=/.test(a));
    const positional = args.filter((a) => !/^\w+\s*=/.test(a));
    const modeArg = kw !== undefined ? kw.replace(/^mode\s*=\s*/, "") : method ? positional[0] : positional[1];
    if (modeArg === undefined || modeArg === "") continue;
    const mode = literal(modeArg);
    if (mode === null || /[wax+]/.test(mode)) return true;
  }
  return false;
}

const WRITES: Record<Exclude<Lang, "other">, (code: string) => boolean> = {
  python: (code) =>
    pythonOpenWrites(code) ||
    /\.(?:write_text|write_bytes|touch|unlink|rename|replace|rmdir|mkdir|symlink_to|hardlink_to|chmod|lchmod)\s*\(/.test(code) ||
    /\bos\.(?:remove|unlink|rename|renames|replace|rmdir|removedirs|makedirs|mkdir|symlink|link|chmod|chown|lchown|truncate|ftruncate|write|utime|mkfifo|mknod)\s*\(/.test(code) ||
    /\bshutil\.(?!which\b)\w+/.test(code) ||
    /\b(?:json|yaml|pickle|marshal|toml|tomli_w)\.dump\s*\(/.test(code) ||
    /\bfrom\s+(?:os|shutil)\s+import\b/.test(code),
  node: (code) =>
    /(?<![\w$])(?:fs\.(?:promises\.)?)?(?:write|append|rm|unlink|rename|copy|cp|symlink|link|mkdir|mkdtemp|chmod|chown|lchown|truncate|ftruncate|utimes|lutimes|futimes|fchmod|fchown)\w*\s*\(/.test(code.replace(/\b(?:process\.)?(?:stdout|stderr)\.write\s*\(/g, "")) ||
    /\bcreateWriteStream\b/.test(code) ||
    /\bopen(?:Sync)?\s*\([^)]*,\s*["'`][wa+]|\bopen(?:Sync)?\s*\([^)]*,\s*[^"'`\s)]/.test(code),
  ruby: (code) =>
    /\bFile\.(?:write|binwrite|delete|unlink|rename|symlink|link|chmod|chown|truncate|utime|mkfifo)\b/.test(code) ||
    /\b(?:File|IO)\.(?:open|new)\s*\(?[^)\n]*,\s*["'][wa+]/.test(code) ||
    /\b(?:File|IO)\.(?:open|new)\s*\(?[^)\n]*,\s*[^"'\s)]/.test(code) ||
    /\bFileUtils\b|\bIO\.(?:write|binwrite)\b|\bDir\.(?:mkdir|rmdir|delete|unlink)\b|\bPathname\b[\s\S]*\.(?:write|delete|unlink|rename|mkpath|rmtree)\b/.test(code),
  perl: (code) =>
    /\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*["'](?:\+?>|>>|\+<|\|)/.test(code) ||
    /\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*["']\s*(?:\+?>|>>|\|)[^"']*["']\s*\)?/.test(code) ||
    /\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*[^"'\s]/.test(code) ||
    /\b(?:unlink|rename|mkdir|rmdir|symlink|link|chmod|chown|utime|truncate|sysopen)\b/.test(code),
  php: (code) =>
    /\b(?:file_put_contents|unlink|rename|copy|mkdir|rmdir|symlink|link|chmod|chown|touch|tempnam|move_uploaded_file)\s*\(/.test(code) ||
    /\bfopen\s*\([^)]*,\s*["'][waxc+]/.test(code) ||
    /\bfopen\s*\([^)]*,\s*[^"'\s)]/.test(code),
  deno: (code) => /\bDeno\.(?:writeTextFile|writeFile|remove|rename|mkdir|symlink|link|chmod|chown|truncate|create|copyFile|makeTemp\w*|utime)\b/.test(code) || /\bDeno\.open(?:Sync)?\s*\([^)]*(?:write|append|create|truncate)\s*:\s*true/.test(code),
  bun: (code) => /\bBun\.write\b/.test(code) || WRITES.node(code),
};

function executes(lang: Lang, code: string): boolean {
  switch (lang) {
    case "python": {
      if (/\b(?:subprocess|os\.system|os\.popen|os\.exec\w*|os\.spawn\w*|os\.posix_spawn\w*|pty\.spawn|runpy|commands\.)\b/.test(code)) return true;
      if (/(?<![\w.])(?:exec|eval|compile|execfile)\s*\(/.test(code)) return true;
      // Importing a module runs it: anything outside the read-only standard modules is code we cannot see.
      for (const m of code.matchAll(/(?:^|[;\n])\s*(?:import\s+([\w.]+(?:\s*,\s*[\w.]+)*)|from\s+([\w.]+)\s+import\b)/g)) {
        const mods = (m[1] ?? m[2] ?? "").split(",").map((x) => x.trim().split(/\s+as\s+/)[0] ?? "");
        if (mods.some((x) => x !== "" && !PY_READ_MODULES.has(x) && !PY_READ_MODULES.has(x.split(".")[0] ?? ""))) return true;
      }
      return false;
    }
    case "node":
    case "deno":
    case "bun": {
      if (/\bchild_process\b|(?<![.\w])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(|\bDeno\.(?:run|Command)\b|\bBun\.(?:spawn|spawnSync|\$)\b|\bworker_threads\b|new\s+Worker\s*\(/.test(code)) return true;
      for (const m of code.matchAll(/\b(?:require|import)\s*\(\s*([^)]*)\)|\bimport\s+[^;'"]*?\bfrom\s+(["'][^"']*["'])|\bimport\s+(["'][^"']*["'])/g)) {
        const arg = (m[1] ?? m[2] ?? m[3] ?? "").trim();
        const lit = literal(arg);
        if (lit === null) return true;
        if (/\.json$/.test(lit)) continue;
        if (NODE_READ_MODULES.has(lit.replace(/^node:/, ""))) continue;
        return true;
      }
      return false;
    }
    case "ruby": {
      if (/\b(?:system|exec|spawn|fork|syscall)\b|`|%x[({[]|\bIO\.popen|\bOpen3\b|\bKernel\.|\bPTY\b/.test(code)) return true;
      for (const m of code.matchAll(/\b(?:require|require_relative|load)\s*\(?\s*["']([^"']+)["']/g)) if (!RUBY_READ_LIBS.has(m[1] as string)) return true;
      return /\b(?:require|require_relative|load)\s*\(?\s*[^"'\s(]/.test(code);
    }
    case "perl": {
      if (/\b(?:system|exec|fork|qx|do|require)\b|`/.test(code)) return true;
      for (const m of code.matchAll(/\buse\s+([\w:]+)/g)) if (!PERL_READ_MODULES.has(m[1] as string)) return true;
      return false;
    }
    case "php":
      return /\b(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec|include|include_once|require|require_once|mail)\b|`/.test(code);
    case "other":
      return true;
  }
}

/** What inline code can do, from the interpreter's language. Any doubt (or an error) means it can write. */
export function capabilities(lang: Lang, code: string): Capabilities {
  if (lang === "other") return { writes: true, executes: true, network: true, dynamic: true };
  try {
    return {
      writes: WRITES[lang](code),
      executes: executes(lang, code),
      network: NETWORK.test(code),
      dynamic: DYNAMIC[lang].test(code) || STRING_BUILT_NAME.test(code),
    };
  } catch {
    return { writes: true, executes: true, network: true, dynamic: true };
  }
}

export function isReadOnly(lang: Lang, caps: Capabilities): boolean {
  return lang !== "other" && !caps.writes && !caps.executes && !caps.network && !caps.dynamic;
}

/** v0.1: file-writing APIs across the interpreters (F5's computed-path check needs one). */
const WRITE_API = /\bopen\s*\([\s\S]{0,400}?,\s*(?:mode\s*=\s*)?["'](?:w|a|x|r\+|w\+|a\+)b?\+?["']|\.write_(?:text|bytes)\s*\(|\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile|copyFileSync|cpSync|renameSync|rmSync|unlinkSync|symlinkSync)\s*\(|\bfs\.(?:promises\.)?(?:write|rm|unlink|rename|copy|cp|symlink|mkdir)|\bshutil\.(?:copy\w*|move|rmtree)|\bos\.(?:rename|replace|remove|unlink|symlink|makedirs)\s*\(|\bFile\.(?:write|open|delete|rename)|\bIO\.write|\bFileUtils\.|\bfile_put_contents|\bfopen\s*\([^)]*["'][wa]|\bunlink\s*\(|\bDeno\.(?:writeTextFile|writeFile|remove|rename)|\bBun\.write/;
/** Signs that a path is assembled at run time rather than written literally. */
const COMPUTED_PATH = /os\.path\.join|expanduser|expandvars|\bPath\s*\(|pathlib|path\.(?:join|resolve)|homedir\s*\(|os\.environ|getenv|process\.env|__dirname|import\.meta|\bf["']|\$\{|["']\s*\+|\+\s*["']|\.format\s*\(|%\s*\(|File\.join|Dir\.home|ENV\[/;

export interface InlineHooks {
  /** Runs a file the code loads (node -e "require('./x.js')"): a downloaded or tainted file is still caught. */
  executeFile: (c: Collector, raw: string, via: string) => void;
}

/** Inline interpreter code: judged by what it names (URLs, paths) and what it can do, never trusted. */
export function inlineCode(name: string, code: string, c: Collector, payload: string, hooks: InlineHooks): void {
  const lang = langOf(name);
  const caps = capabilities(lang, code);
  const readOnly = isReadOnly(lang, caps);
  const opaque = !readOnly && OPAQUE_CODE.test(code);
  addEffect(c, { cls: opaque ? "execute_opaque" : "execute", target: name, detail: opaque ? `run inline ${name} code that uses the network, other programs or decoding` : `run inline ${name} code${readOnly ? " that only reads" : ""}` });
  const codeUrls = [...code.matchAll(/\b(?:https?|wss?|ftp):\/\/[^\s'"`<>\\)]+/g)].map((m) => m[0]);
  for (const u of codeUrls) egress(c, u, opaque ? "send" : "fetch", { payload, via: `inline ${name} code` });
  taintFetched(c, codeUrls, `inline ${name} code`);
  // F5: code that writes files to a path built at run time cannot be checked against the protected
  // list; in an untrusted session that is the riskiest case, so a person decides.
  if (c.state.tainted && WRITE_API.test(code) && (COMPUTED_PATH.test(code) || !/["'`](?:~|\/|\.{0,2}\/|[\w.-]+\.[\w]+)/.test(code))) {
    addFinding(c, "unresolvable_write_target", `inline ${name} code writes files at a path computed at run time`);
  }
  // Files the code loads as code (node: require/import of a relative or absolute path) run.
  if (lang === "node" || lang === "deno" || lang === "bun") {
    for (const m of code.matchAll(/\b(?:require|import)\s*\(\s*["'`]((?:\.{1,2}|~)?\/[^"'`]+)["'`]\s*\)/g)) {
      if (!/\.json$/.test(m[1] as string)) hooks.executeFile(c, m[1] as string, `${name} require`);
    }
  }
  // Quoted path literals: read-only code reads them; code that can write may read or write any of them.
  for (const m of code.matchAll(/["'`]((?:~|\/|\.{1,2}\/|\$HOME)[^"'`\n]{0,300}|[^"'`\n/]*\.(?:env|pem|key)|[^"'`\n]*(?:\.claude|\.cursor|\.mcp\.json|CLAUDE\.md|AGENTS\.md|MEMORY\.md|\.ssh|\.aws)[^"'`\n]*)["'`]/g)) {
    const lit = m[1] as string;
    const probe = { ...c, effects: [] as typeof c.effects, findings: [] as typeof c.findings };
    readPath(probe, lit, { via: `inline ${name} code` });
    if (!readOnly) writePath(probe, lit, { via: `inline ${name} code` });
    for (const e of probe.effects) if (e.cls !== "write_workspace" && e.cls !== "read_local_workspace" && e.cls !== "write_outside_workspace") addEffect(c, e);
    for (const f of probe.findings) if (f.id !== "unresolvable_write_target") addFinding(c, f.id, f.detail);
  }
  if (/\b(?:os\.environ|process\.env|ENV\[|getenv|\$ENV\{|System\.getenv|Deno\.env)\b/.test(code) && !/\b(?:os\.environ|process\.env|ENV)\s*(?:\.get\s*\(|\[)\s*["'](?:NODE_ENV|PATH|HOME|PWD|CI|DEBUG|PORT|LANG|TERM|USER)["']/.test(code)) {
    addEffect(c, { cls: "read_secret", target: "environment", detail: `read environment variables from inline ${name} code`, private: true, tags: ["env-var"] });
  }
}
