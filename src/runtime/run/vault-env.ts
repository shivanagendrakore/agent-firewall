/**
 * `run --env NAME=vault://…` (see docs/vault.md): the values a run puts into its child's environment, and
 * the filter that keeps them out of what the child prints.
 *
 * Two ways in, and nothing else lets a value out:
 *
 * - **a ticket** (`--ticket T`): the hook decided a shell command with
 *   references (Claude Code's rewrite into a ticketed run) and left a
 *   single-use ticket bound to the exact `--env` pairs and argv
 *   (src/runtime/vault/tickets.ts). consumeTicket() spends it; the values
 *   are read for the substitutions the hook allowed, from the signed index
 *   as it is now (a binding revoked since then stops it).
 * - **a process binding** (no ticket; a person's own run): every reference
 *   must name a secret bound with `vault allow <name> --process "<argv>"`
 *   to a pattern that matches this exact argv.
 *
 * Any refusal exits 77 and logs vault_denied, before the child starts. The
 * values live in this process's memory and the child's environment only:
 * never in an argument, a log entry or a file.
 */

import { dirname, isAbsolute, resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { isUnder, PROTECTION_FOLDS_CASE } from "../../engine/paths.js";
import { realpathLoose } from "../realpath.js";
import { bindingSummary, formatRef, parseRef, processBindingMatches, vaultFingerprints, type VaultView } from "../../engine/vault-ref.js";
import { DUMP_ROW, encodings, scrubText, type KnownValue } from "../../engine/vault-scrub.js";
import { withRotatingPrints } from "../../gateway/oauth-vault.js";
import type { VaultSubstitution } from "../../types.js";
import type { Layout } from "../layout.js";
import { loadIndex, vaultView } from "../vault/index.js";
import { logDenied, logUse, readValues, type BackendFor } from "../vault/substitute.js";
import { consumeTicket } from "../vault/tickets.js";
import { setOwn } from "../../own.js";

/** The exit status of a refused substitution (EX_NOPERM). */
export const EXIT_VAULT_DENIED = 77;

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
/** Variables run sets or relies on: a secret may not replace them. */
const RESERVED = /^(?:LAUNCHSAFE_FIREWALL_\w*|(?:https?|all|no|ftp|socks)_proxy|NODE_USE_ENV_PROXY|TMPDIR|PATH|HOME|LD_\w+|DYLD_\w+|NODE_OPTIONS)$/i;

/**
 * I6: the only variables a ticketed sender inherits from the agent's shell (the values are added on top):
 * where programs are, the home directory, the locale, the terminal and the time zone. Everything else
 * (proxies, resolver overrides, TLS trust and key logging, config files, the loader, and whatever else the
 * agent set) stays out, so the value goes only to the host the hook checked, by the system's own name
 * resolution and trust. PATH only finds the shell's builtins' helpers: the sender is named by its absolute path.
 */
export const TICKET_ENV: readonly string[] = ["PATH", "HOME", "LANG", "TERM", "TZ"];

/** The environment a ticketed sender starts with: TICKET_ENV and the locale's LC_* variables, nothing else. */
export function ticketBaseEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(env).filter(([k, v]) => v !== undefined && (TICKET_ENV.includes(k) || /^LC_[A-Z]+$/.test(k))));
}

/** Parses the `--env NAME=vault://…` values; an error names the bad one. */
export function parseEnvPairs(raw: readonly string[]): { ok: true; pairs: [string, string][] } | { ok: false; why: string } {
  const pairs: [string, string][] = [];
  for (const r of raw) {
    const eq = r.indexOf("=");
    const name = eq === -1 ? r : r.slice(0, eq);
    const ref = eq === -1 ? "" : r.slice(eq + 1);
    if (!ENV_NAME.test(name)) return { ok: false, why: `--env ${name.slice(0, 64)}: not an environment variable name` };
    if (RESERVED.test(name)) return { ok: false, why: `--env ${name}: run sets this variable itself` };
    if (parseRef(ref) === null) return { ok: false, why: `--env ${name}: the value must be a vault reference (vault://name or vault://name#field), never the secret itself` };
    if (pairs.some(([n]) => n === name)) return { ok: false, why: `--env ${name} given twice` };
    pairs.push([name, ref]);
  }
  return { ok: true, pairs };
}

export type RunEnv = { ok: true; env: Record<string, string>; values: KnownValue[]; session: string; ticketed: boolean; view: VaultView } | { ok: false; why: string };

export interface RunEnvOptions {
  ticket?: string;
  pairs: readonly (readonly [string, string])[];
  /** The child's argv exactly as given (the words after "--"). */
  argv: readonly string[];
  /** A person's run: the absolute path run resolved argv[0] to, and will start (I7). */
  program?: string;
  /** A person's run: the workspace; a bare-name binding never matches a program inside it (I7). */
  workspace?: string;
  trustedKey: string | null;
  backendFor: BackendFor;
  /** A name for the log when there is no ticket (the run's id). */
  runId: string;
  now?: Date;
}

/**
 * I7: whether a process binding admits the program run will start. A binding that names the program by an
 * absolute path matches only that file (symlinks resolved on both sides); a relative path never matches (it
 * would name a different file in every directory). A bare name matches the argv word for word, as before,
 * and only when the program it resolved to is outside the workspace (a `deploy` the agent put on a
 * workspace-relative PATH entry, node_modules/.bin, is never the one you bound).
 */
export function processBindingFor(pattern: readonly string[], o: { argv: readonly string[]; program?: string; workspace?: string }): boolean {
  const p0 = pattern[0];
  if (p0 === undefined) return false;
  if (p0.includes("/")) {
    if (!isAbsolute(p0) || o.program === undefined) return false;
    return realpathLoose(p0) === realpathLoose(o.program) && processBindingMatches(["-", ...pattern.slice(1)], ["-", ...o.argv.slice(1)]);
  }
  if (!processBindingMatches(pattern, o.argv)) return false;
  if (o.program === undefined) return false;
  if (o.workspace !== undefined) {
    // I1: a program that could be inside the workspace under another spelling is not the one you bound (case folded on every platform).
    const ci = PROTECTION_FOLDS_CASE;
    const ws = realpathLoose(o.workspace);
    const rawWs = resolve(o.workspace);
    const prog = resolve(o.program);
    const realProg = realpathLoose(o.program);
    const realProgDir = realpathLoose(dirname(prog));
    if (
      isUnder(prog, ws, ci) ||
      isUnder(prog, rawWs, ci) ||
      isUnder(realProg, ws, ci) ||
      isUnder(realProg, rawWs, ci) ||
      isUnder(realProgDir, ws, ci) ||
      isUnder(realProgDir, rawWs, ci)
    ) {
      return false;
    }
  }
  return true;
}

/** The values for this run's `--env` pairs, or a refusal (already logged as vault_denied). */
export function resolveRunEnv(l: Layout, o: RunEnvOptions): RunEnv {
  const refs = o.pairs.map(([, r]) => r);
  const deny = (session: string, why: string, rule?: string): RunEnv => {
    try {
      logDenied(l, { session, refs, problem: why, ...(rule !== undefined ? { rule } : {}), extra: { via: "run" } });
    } catch {
      // The refusal stands without its log entry.
    }
    return { ok: false, why };
  };
  let subs: VaultSubstitution[];
  let session: string;
  const st = loadIndex(l, o.trustedKey);
  if (st.state !== "ok") return deny(o.runId !== undefined ? `run:${o.runId}` : "run:unknown", st.state === "unsigned" ? `the vault index does not verify: ${st.reason}` : st.state === "corrupt" ? st.error : "the vault is empty");
  
  if (o.ticket !== undefined) {
    const t = consumeTicket(l, o.ticket, o.pairs, o.argv, o.now);
    if (!t.ok) return deny(`run:${o.runId}`, `ticket refused: ${t.why}`);
    session = t.session;
    subs = t.substitute;
    // The ticket covers exactly these pairs (its hash says so); every reference must have an allowed substitution.
    const missing = refs.find((r) => !subs.some((s) => s.ref === r));
    if (missing !== undefined) return deny(session, `${missing} was not allowed by the decision that issued the ticket`);
  } else {
    session = `run:${o.runId}`;
    subs = [];
    for (const r of refs) {
      const ref = parseRef(r);
      const e = ref === null ? undefined : st.index.entries.find((x) => x.name === ref.name);
      if (ref === null || e === undefined) return deny(session, `${r}: no such secret`);
      const field = ref.field ?? (e.fields.length === 1 ? (e.fields[0] as string) : "");
      if (!e.fields.includes(field)) return deny(session, `${r}: name a field (${e.fields.map((f) => formatRef(e.name, f)).join(", ")})`);
      const b = e.bindings.find((x) => x.kind === "process" && processBindingFor(x.argv, o));
      if (b === undefined) return deny(session, `${r} is not bound to this command (vault allow ${e.name} --process "<command>")`, "FW-VAULT-UNBOUND");
      subs.push({ ref: r, name: e.name, field, kind: e.kind, via: "run", destination: o.argv.join(" ").slice(0, 200), binding: bindingSummary(b) });
    }
  }
  const read = readValues(l, subs, o.trustedKey, o.backendFor);
  if (!read.ok) return deny(session, `${read.ref}: ${read.why}`);
  const env: Record<string, string> = {};
  for (const [name, r] of o.pairs) {
    const v = read.values.find((k) => k.ref === r);
    if (v === undefined) return deny(session, `${r}: no value was read`);
    // A ticketed wget reads the value inside a configuration line: a line break would add commands to it.
    // The vault refuses such values when they are stored; checked again here, where it matters.
    if (/[\r\n\0]/.test(v.value)) return deny(session, `${r}: the stored value holds a line break or NUL`);
    setOwn(env, name, v.value);
  }
  if (o.ticket === undefined) {
    for (const s of subs) {
      try {
        logUse(l, s, { session, action: "run", verdict: "allow" });
      } catch {
        // The use is not refused for a missing log entry; doctor reports the log.
      }
    }
  }
  return { ok: true, env, values: read.values, session, ticketed: o.ticket !== undefined, view: withRotatingPrints(l, vaultView(st)) as VaultView };
}

export const WITHHELD_SEGMENT = "[LaunchSafe Firewall withheld output that carried a value stored in the vault]";

/** How much of one dump is held back before it is withheld unread (fail closed). */
const MAX_DUMP = 4 * 1024 * 1024;

/**
 * Holds back the rows of a dump (curl --trace -, hexdump, xxd) until the dump ends, so a value split over
 * rows is judged whole (V16): a block in which any value can be read back is replaced by the withheld note.
 * Everything else passes straight through to the value filter.
 */
class DumpHold {
  private partial = "";
  private block = "";

  constructor(
    private readonly known: readonly KnownValue[],
    private readonly view?: VaultView
  ) {}

  push(text: string): string {
    const all = this.partial + text;
    this.partial = "";
    let out = "";
    let at = 0;
    while (at < all.length) {
      const nl = all.indexOf("\n", at);
      if (nl === -1) {
        const rest = all.slice(at);
        // A line still coming may be a dump row (or a block's next row): hold it, within reason.
        if ((this.block !== "" || /^[0-9a-fA-F]{0,8}(?::? {0,2}.*)?$/.test(rest)) && rest.length < 4096) this.partial = rest;
        else out += this.flush() + rest;
        break;
      }
      const line = all.slice(at, nl + 1);
      if (DUMP_ROW.test(line.replace(/\r?\n$/, ""))) {
        this.block += line;
        if (this.block.length > MAX_DUMP) {
          this.block = "";
          out += `${WITHHELD_SEGMENT}\n`;
        }
      } else out += this.flush() + line;
      at = nl + 1;
    }
    return out;
  }

  end(): string {
    const rest = this.partial;
    this.partial = "";
    if (rest !== "" && DUMP_ROW.test(rest)) {
      this.block += rest;
      return this.flush();
    }
    return this.flush() + rest;
  }

  private flush(): string {
    const b = this.block;
    this.block = "";
    if (b === "") return "";
    return scrubText(b, this.known, this.view).leftover ? `${WITHHELD_SEGMENT}\n` : b;
  }
}

/**
 * A streaming filter for the child's output: every value (and its encodings) becomes its reference. It
 * holds back the last few characters of each chunk, so a value split across two chunks is still replaced.
 */
export class OutputScrubber {
  private carry = "";
  private readonly decoder = new StringDecoder("utf8");
  private readonly active: boolean;
  private readonly hold: number;
  private readonly dumps: DumpHold;

  constructor(
    private readonly known: readonly KnownValue[],
    private readonly view?: VaultView
  ) {
    // x3: a value is also recognised percent-encoded (three characters per byte), not only as hex (two).
    const viewLens = vaultFingerprints(view).map((fp) => (Number(fp.split(":")[0]) || 0) * 3);
    const maxLen = Math.max(0, ...known.flatMap((k) => encodings(k.value).map((e) => e.length)), ...viewLens);
    this.active = maxLen > 0;
    this.hold = Math.max(0, maxLen - 1);
    this.dumps = new DumpHold(known, view);
  }

  /** What may be written now. */
  push(chunk: Buffer | string): string {
    const raw = typeof chunk === "string" ? chunk : this.decoder.write(chunk);
    const text = this.carry + (!this.active ? raw : this.dumps.push(raw));
    if (!this.active) {
      this.carry = "";
      return text;
    }
    const r = scrubText(text, this.known, this.view);
    if (r.leftover) {
      this.carry = "";
      return WITHHELD_SEGMENT;
    }
    const cut = Math.max(0, r.value.length - this.hold);
    this.carry = r.value.slice(cut);
    return r.value.slice(0, cut);
  }

  /** The rest, at the end of the stream. */
  end(): string {
    const rest = this.decoder.end();
    const tail = this.carry + (!this.active ? rest : this.dumps.push(rest) + this.dumps.end());
    this.carry = "";
    if (tail === "" || !this.active) return tail;
    const r = scrubText(tail, this.known, this.view);
    return r.leftover ? WITHHELD_SEGMENT : r.value;
  }
}

export interface TicketedRunOptions {
  argv: readonly string[];
  /** The environment the child inherits; the --env values are added on top. */
  base: NodeJS.ProcessEnv;
  extra: Record<string, string>;
  values: readonly KnownValue[];
  view?: VaultView;
  cwd: string;
  /** Where the child's filtered standard output and error go (raw text, no newline added). */
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

/**
 * The hook's rewrite of a shell command, run as decided: the command itself was checked by the hook like
 * any other (so no sandbox is added here, which would change what the person approved), with the values in
 * its environment and its output filtered back to the references before the agent reads it.
 */
export async function runTicketed(o: TicketedRunOptions): Promise<number> {
  const { spawn } = await import("node:child_process");
  const out = new OutputScrubber(o.values, o.view);
  const err = new OutputScrubber(o.values, o.view);
  return new Promise<number>((done) => {
    let child: import("node:child_process").ChildProcess;
    try {
      child = spawn(o.argv[0] as string, o.argv.slice(1), { cwd: o.cwd, env: { ...o.base, ...o.extra }, stdio: ["inherit", "pipe", "pipe"] });
    } catch (e) {
      o.stderr(`launchsafe-firewall run: could not start ${String(o.argv[0]).slice(0, 200)}: ${(e as Error).message}\n`);
      done(127);
      return;
    }
    child.stdout?.on("data", (c: Buffer) => o.stdout(out.push(c)));
    child.stderr?.on("data", (c: Buffer) => o.stderr(err.push(c)));
    child.on("error", (e) => {
      o.stderr(`launchsafe-firewall run: could not start ${String(o.argv[0]).slice(0, 200)}: ${e.message}\n`);
      done(127);
    });
    child.on("close", (code, signal) => {
      o.stdout(out.end());
      o.stderr(err.end());
      done(code ?? (signal !== null ? 128 + 15 : 1));
    });
  });
}
