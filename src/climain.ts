/**
 * launchsafe-firewall: the hook entry point and the commands a person uses.
 * Arguments are parsed against the declared specs in cliargs.ts before any
 * handler runs, so help and usage errors never have side effects. Changing
 * commands (queue approve, install, uninstall) are refused when the firewall
 * sees an agent run them, and approvals also require a terminal.
 */

import { readFileSync, readSync, rmSync, statSync, writeSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { dirname, join, resolve } from "node:path";
import { stripBom } from "./bom.js";
import { COMMANDS, helpText, parseCommandLine, usageError, type CommandSpec, type Parsed } from "./cliargs.js";
import type { CanaryKind } from "./runtime/canaries.js";
import { layout, type Layout } from "./runtime/layout.js";
import { platformSupported, unsupportedPlatformMessage } from "./runtime/platform.js";
import { VERSION } from "./version.js";
import { safeLine, safeText } from "./engine/terminal.js";
import type { VaultCliDeps } from "./vault-cli.js";
import type { MailCliDeps } from "./mail-cli.js";
import type { PhoneCliDeps } from "./phone-cli.js";
import type { SessionCliDeps } from "./session-cli.js";
import type { LearnedCliDeps } from "./learned-cli.js";
import { own } from "./own.js";

export const EXIT_USAGE = 64;

/**
 * R6: every line a command prints passes through safeText, because much of it is agent- or
 * repository-written (queue reasons and proposals, MCP launch lines, log entries, doctor findings).
 * Control characters are shown as \uXXXX, which inside JSON output is the same character, so --json
 * still parses to the same value.
 */
/** Where output goes: the process's fds, or (tests calling main() in-process) a capture. */
let write: (fd: 1 | 2, s: string) => void = (fd, s) => void writeSync(fd, s);

function out(s: string): void {
  const t = safeText(s, { keepTabs: true });
  write(1, t.endsWith("\n") ? t : `${t}\n`);
}

function err(s: string): void {
  const t = safeText(s, { keepTabs: true });
  write(2, t.endsWith("\n") ? t : `${t}\n`);
}

/**
 * The most standard input the CLI reads (a hook event, a `check` request): 64 MiB, the hook's own input bound.
 * Past it the read stops, so an oversized event never fills memory, and the command fails closed with a clear
 * error (the hook blocks the action, exit 2).
 */
export const MAX_STDIN_BYTES = 64 * 1024 * 1024;

export class StdinTooLarge extends Error {
  constructor(max: number) {
    super(`the input on standard input is larger than ${max / (1024 * 1024)} MiB`);
  }
}

/**
 * Reads a file descriptor to its end, at most `max` bytes (StdinTooLarge past it), without a leading UTF-8 byte
 * order mark (a Windows shell's pipe puts one there). Any other read error gives ""
 * (the callers then fail on the empty input, as before).
 */
export function readBounded(fd: number, max = MAX_STDIN_BYTES): string {
  const chunks: Buffer[] = [];
  let total = 0;
  const buf = Buffer.alloc(1024 * 1024);
  try {
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > max) throw new StdinTooLarge(max);
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
  } catch (e) {
    if (e instanceof StdinTooLarge) throw e;
    return "";
  }
  return stripBom(Buffer.concat(chunks, total).toString("utf8"));
}

/** Tests calling main() in-process only: standard input read from this descriptor, with this bound. */
let stdinOverride: { fd: number; max?: number } | null = null;

/** Standard input, at most MAX_STDIN_BYTES (the only bound on a hook event's size: runHook takes what this returns). */
function readStdin(): string {
  return stdinOverride === null ? readBounded(0) : readBounded(stdinOverride.fd, stdinOverride.max);
}

type Ok = Extract<Parsed, { kind: "ok" }>;

function flag(p: Ok, name: string): boolean {
  return p.flags.get(name) === true;
}

function opt(p: Ok, name: string): string | undefined {
  const v = p.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

/** Tests calling main() in-process only (no argument, variable or file reaches it from the CLI binary). */
let keyboardCheck: (() => Promise<boolean>) | null = null;
/** Tests calling main() in-process only: a fake vault store and scripted terminal input. */
let vaultOverrides: Partial<VaultCliDeps> = {};
/** Tests calling main() in-process only: scripted terminal input for the scratch commands. */
let scratchOverrides: Partial<import("./scratch-cli.js").ScratchCliDeps> = {};
/** Tests calling main() in-process only: scripted terminal input for the email guard's commands. */
let mailOverrides: Partial<MailCliDeps> = {};
/** Tests calling main() in-process only: a stub relay client, scripted input, a fake service manager. */
let phoneOverrides: Partial<PhoneCliDeps> = {};
/** Tests calling main() in-process only: scripted terminal input for the kill switch's commands. */
let sessionOverrides: Partial<SessionCliDeps> = {};
/** Tests calling main() in-process only: scripted terminal input for the learned-choice commands. */
let learnedOverrides: Partial<LearnedCliDeps> = {};
/** Tests calling main() in-process only: the vault store and the environment `run --env` uses. */
let runOverrides: RunOverrides = {};

export interface RunOverrides {
  backendFor?: import("./runtime/vault/substitute.js").BackendFor;
  env?: NodeJS.ProcessEnv;
}

/**
 * Commands that change what the firewall allows run only for a person: in a real terminal, and not as a
 * descendant of a Claude Code session (an agent can fake a terminal, it cannot stop being Claude Code's
 * child). The approval passphrase, checked separately, is what actually authorizes the change.
 */
async function humanAtKeyboard(): Promise<boolean> {
  if (keyboardCheck !== null) return keyboardCheck();
  const { agentLaunch } = await import("./runtime/approver.js");
  if (process.stdin.isTTY !== true || process.stdout.isTTY !== true) {
    err("This command changes what the firewall allows, so it only runs in an interactive terminal (a person at the keyboard), not from a script or an agent.");
    return false;
  }
  const why = agentLaunch();
  if (why === "unknown") {
    err(`${unreadAncestry("This command")} The agent may not approve its own actions.`);
    return false;
  }
  if (why !== null) {
    err("This command was started from inside a coding agent's session (Claude Code, Codex, Gemini CLI or Cursor). Run it in a separate terminal window of your own; the agent may not approve its own actions.");
    return false;
  }
  return true;
}

/**
 * The refusal when agentLaunch() could not finish its walk. A process the command was started from could not be
 * read, which is not the same as an agent having started it, so the message does not say that one did.
 */
function unreadAncestry(what: string): string {
  return `${what} could not read every process it was started from (on Linux, /proc mounted with hidepid hides other users' processes, sshd's among them), so it cannot rule out that an agent started it (docs/limitations.md, Approvals).`;
}

/**
 * For the commands that need no terminal but may not be started by an agent (the kill switch's stop, the local
 * API's commands, openshell serve): false when an agent started this process, after printing the command's own
 * `refusal`, or when a process it was started from could not be read, after saying that instead.
 */
async function notAgent(refusal: string): Promise<boolean> {
  if (keyboardCheck !== null) {
    if (await keyboardCheck()) return true;
    err(refusal);
    return false;
  }
  const { agentLaunch } = await import("./runtime/approver.js");
  const why = agentLaunch();
  if (why === null) return true;
  err(why === "unknown" ? unreadAncestry("This command") : refusal);
  return false;
}

/** Tests calling main() in-process only: the platform the support check sees (the CLI binary always sees process.platform). */
let platformOverride: NodeJS.Platform | null = null;

/** The commands that only say what the firewall is and run anywhere; every other command needs a supported platform. */
const ANY_PLATFORM: ReadonlySet<string> = new Set(["help", "version"]);

/**
 * The exit code of a command refused because this platform is not supported (macOS and Linux are), or null. The hook
 * blocks the action with exit 2, like every other hook failure, so the agent does not run what it could not judge;
 * the other commands print the reason and exit 1, and nothing is read or written first.
 */
function platformRefusal(spec: CommandSpec): number | null {
  const platform = platformOverride ?? process.platform;
  const key = spec.path.join(" ");
  if (platformSupported(platform) || ANY_PLATFORM.has(key)) return null;
  if (key === "hook") {
    err(`${unsupportedPlatformMessage(platform)} It cannot judge this action, so it blocked it. Remove the firewall's hook from the agent's settings, or run the agent on macOS or Linux.`);
    return 2;
  }
  err(`launchsafe-firewall: ${unsupportedPlatformMessage(platform)} This command did not run (docs/limitations.md, Platforms).`);
  return 1;
}

/** Tests calling main() in-process only: scripted passphrase input (no argument, variable or file reaches it from the CLI binary). */
let secretReader: ((prompt: string) => Promise<string>) | null = null;

/** Reads a line from the terminal without echoing it. */
function readSecret(prompt: string): Promise<string> {
  if (secretReader !== null) return secretReader(prompt);
  return new Promise((resolveSecret, reject) => {
    const stdin = process.stdin;
    writeSync(1, prompt);
    let value = "";
    const done = (fn: () => void): void => {
      stdin.setRawMode?.(false);
      stdin.pause();
      stdin.removeListener("data", onData);
      writeSync(1, "\n");
      fn();
    };
    const onData = (buf: Buffer): void => {
      for (const ch of buf.toString("utf8")) {
        if (ch === "\r" || ch === "\n") return done(() => resolveSecret(value));
        if (ch === "\u0003") return done(() => reject(new Error("cancelled")));
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}

async function newPassphrase(): Promise<string> {
  const { MIN_PASSPHRASE, passphraseProblem } = await import("./runtime/approver.js");
  for (let i = 0; i < 3; i++) {
    const a = await readSecret(`New approval passphrase (at least ${MIN_PASSPHRASE} characters, several words work well; never type it into the agent): `);
    const b = await readSecret("Repeat it: ");
    const problem = passphraseProblem(a);
    if (a !== b) err("They did not match.");
    else if (problem !== null) err(`Not strong enough: ${problem}.`);
    else return a;
  }
  throw new Error("no passphrase set");
}

type Handler = (p: Ok, l: Layout) => Promise<number>;

/** The vault's commands live in vault-cli.ts; this hands them the terminal and the real stores. */
function vaultCommand(key: string): Handler {
  return async (p, l) => {
    const { VAULT_HANDLERS } = await import("./vault-cli.js");
    const { openBackend, backendAvailable } = await import("./runtime/vault/backends.js");
    const ask = async (q: string): Promise<string> => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        return await rl.question(q);
      } finally {
        rl.close();
      }
    };
    const deps: VaultCliDeps = { out, err, humanAtKeyboard, readSecret, ask, openBackend, available: (id) => backendAvailable(id), platform: process.platform, env: process.env, cwd: process.cwd(), ...vaultOverrides };
    const h = own(VAULT_HANDLERS, key);
    if (h === undefined) throw new Error(`no vault handler for ${key}`);
    return h(p, l, deps);
  };
}

/** The scratch-target commands live in scratch-cli.ts. */
function scratchCommand(key: string): Handler {
  return async (p, l) => {
    const { SCRATCH_HANDLERS } = await import("./scratch-cli.js");
    const h = own(SCRATCH_HANDLERS, key);
    if (h === undefined) throw new Error(`no scratch handler for ${key}`);
    return h(p, l, { out, err, humanAtKeyboard, readSecret, ...scratchOverrides });
  };
}

/** The known-hosts commands live in hosts-cli.ts. */
function hostsCommand(key: string): Handler {
  return async (p, l) => {
    const { HOSTS_HANDLERS } = await import("./hosts-cli.js");
    const h = own(HOSTS_HANDLERS, key);
    if (h === undefined) throw new Error(`no hosts handler for ${key}`);
    return h(p, l, { out, err, humanAtKeyboard, readSecret, cwd: process.cwd() });
  };
}

/** "Fewer prompts": `friction` and the `allow` commands live in learned-cli.ts. */
function learnedCommand(key: string): Handler {
  return async (p, l) => {
    const { LEARNED_HANDLERS } = await import("./learned-cli.js");
    const { terminalWidth } = await import("./runtime/report.js");
    const ask = async (q: string): Promise<string> => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        return await rl.question(q);
      } finally {
        rl.close();
      }
    };
    const deps: LearnedCliDeps = { out, err, humanAtKeyboard, readSecret, ask, cwd: process.cwd(), width: terminalWidth(process.stdout.columns), ...learnedOverrides };
    const h = own(LEARNED_HANDLERS, key);
    if (h === undefined) throw new Error(`no handler for ${key}`);
    return h(p, l, deps);
  };
}

/** The local API's commands live in api-cli.ts. */
function apiCommand(key: string): Handler {
  return async (p, l) => {
    const { API_HANDLERS } = await import("./api-cli.js");
    const h = own(API_HANDLERS, key);
    if (h === undefined) throw new Error(`no api handler for ${key}`);
    return h(p, l, { out, err, notAgent, humanAtKeyboard, readSecret, cwd: process.cwd(), env: process.env });
  };
}

/** The kill switch's commands live in session-cli.ts. */
function sessionCommand(key: string): Handler {
  return async (p, l) => {
    const { sessionHandler } = await import("./session-cli.js");
    return sessionHandler(key)(p, l, { out, err, notAgent, humanAtKeyboard, readSecret, env: process.env, ...sessionOverrides });
  };
}

/** NVIDIA OpenShell's commands live in openshell-cli.ts (docs/sandboxes.md). */
function openshellCommand(key: string): Handler {
  return async (p, l) => {
    const { OPENSHELL_HANDLERS } = await import("./openshell-cli.js");
    const h = own(OPENSHELL_HANDLERS, key);
    if (h === undefined) throw new Error(`no openshell handler for ${key}`);
    return h(p, l, { out, err, notAgent, cwd: process.cwd(), env: process.env });
  };
}

/** The gateway's commands live in gateway-cli.ts. */
function gatewayCommand(key: string): Handler {
  return async (p, l) => {
    const { GATEWAY_HANDLERS } = await import("./gateway-cli.js");
    const { homedir } = await import("node:os");
    const ask = async (q: string): Promise<string> => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        return await rl.question(q);
      } finally {
        rl.close();
      }
    };
    const h = own(GATEWAY_HANDLERS, key);
    if (h === undefined) throw new Error(`no gateway handler for ${key}`);
    return h(p, l, { out, err, humanAtKeyboard, readSecret, ask, env: process.env, cwd: process.cwd(), platform: process.platform, home: homedir() });
  };
}

/** The email guard's commands live in mail-cli.ts; this hands them the terminal. */
function mailCommand(key: string): Handler {
  return async (p, l) => {
    const { MAIL_HANDLERS } = await import("./mail-cli.js");
    const ask = async (q: string): Promise<string> => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        return await rl.question(q);
      } finally {
        rl.close();
      }
    };
    const deps: MailCliDeps = { out, err, humanAtKeyboard, readSecret, ask, cwd: process.cwd(), ...mailOverrides };
    const h = own(MAIL_HANDLERS, key);
    if (h === undefined) throw new Error(`no mail handler for ${key}`);
    return h(p, l, deps);
  };
}

/** The phone and relay commands live in phone-cli.ts; this hands them the terminal, the relay client and the service manager. */
function phoneCommand(key: string): Handler {
  return async (p, l) => {
    const { PHONE_HANDLERS } = await import("./phone-cli.js");
    const ask = async (q: string): Promise<string> => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        return await rl.question(q);
      } finally {
        rl.close();
      }
    };
    const client = (base: string, lay: Layout): import("./runtime/relay/client.js").RelayClient => {
      // Loaded lazily: only phone pair and relay run ever reach the network.
      let made: import("./runtime/relay/client.js").RelayClient | null = null;
      const get = async (): Promise<import("./runtime/relay/client.js").RelayClient> => {
        if (made !== null) return made;
        const { HttpRelayClient } = await import("./runtime/relay/client.js");
        const { readDevice } = await import("./runtime/relay/keys.js");
        made = new HttpRelayClient({ base, device: () => {
          const d = readDevice(lay);
          if (d === null) throw new Error("no relay identity on this machine");
          return d;
        } });
        return made;
      };
      return {
        startPairing: async (r) => (await get()).startPairing(r),
        pairingStatus: async (id) => (await get()).pairingStatus(id),
        confirmPairing: async (id) => (await get()).confirmPairing(id),
        uploadItems: async (i) => (await get()).uploadItems(i),
        withdraw: async (ref, why) => (await get()).withdraw(ref, why),
        decisions: async (after, wait) => (await get()).decisions(after, wait),
        summary: async (x) => (await get()).summary(x),
      };
    };
    const { spawnSync } = await import("node:child_process");
    const deps: PhoneCliDeps = {
      out,
      err,
      raw: (line) => write(1, `${line}\n`),
      ansi: process.stdout.isTTY === true,
      humanAtKeyboard,
      readSecret,
      ask,
      client,
      run: (cmd, args) => {
        const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 15000 });
        return { status: r.status ?? 1, stderr: r.stderr ?? "" };
      },
      platform: process.platform,
      sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
      ...phoneOverrides,
    };
    const h = own(PHONE_HANDLERS, key);
    if (h === undefined) throw new Error(`no phone handler for ${key}`);
    return h(p, l, deps);
  };
}

/**
 * `run --ticket T --env …`: the hook's rewrite of a shell command with vault references, run in
 * the agent's own shell. The ticket is the authorization: the hook decided this exact command and issued it,
 * single-use, so this path needs no person at the keyboard and adds no sandbox. Anything else is refused.
 */
async function runWithTicket(p: Ok, l: Layout, ticket: string, envRaw: readonly string[], baseEnv: NodeJS.ProcessEnv): Promise<number> {
  const { parseEnvPairs, resolveRunEnv, runTicketed, ticketBaseEnv, EXIT_VAULT_DENIED } = await import("./runtime/run/vault-env.js");
  const extra = ["--workspace", "--allow-write", "--send-host", "--allow-localhost", "--allow-keychain", "--git-init", "--dry-run", "--verbose", "--agent"].filter((f) => p.flags.has(f));
  if ((p.lists?.get("--pass-env") ?? []).length > 0) extra.push("--pass-env");
  if ((p.lists?.get("--allow-home-read") ?? []).length > 0) extra.push("--allow-home-read");
  if (extra.length > 0) {
    err(`launchsafe-firewall run: --ticket runs exactly what the hook decided; ${extra.join(", ")} cannot be added to it.`);
    return EXIT_USAGE;
  }
  const parsed = parseEnvPairs(envRaw);
  if (!parsed.ok) {
    err(`launchsafe-firewall run: ${parsed.why}`);
    return EXIT_USAGE;
  }
  const { trustedApproverKey } = await import("./hook/pipeline.js");
  const { defaultBackendFor } = await import("./runtime/vault/substitute.js");
  const got = resolveRunEnv(l, { ticket, pairs: parsed.pairs, argv: p.positionals, trustedKey: trustedApproverKey(l, baseEnv), backendFor: runOverrides.backendFor ?? defaultBackendFor(l), runId: "ticket" });
  if (!got.ok) {
    err(`launchsafe-firewall run: refused: ${got.why}`);
    return EXIT_VAULT_DENIED;
  }
  return runTicketed({ argv: p.positionals, base: ticketBaseEnv(baseEnv), extra: got.env, values: got.values, view: got.view, cwd: process.cwd(), stdout: (t) => t !== "" && write(1, t), stderr: (t) => t !== "" && write(2, t) });
}

/** I3: how much of one held value the approval screens print (the queue stores at most 20,000 characters per text). */
const SHOW_CHARS = 20000;

async function queueDecide(p: Ok, l: Layout, sub: "approve" | "reject" | "review"): Promise<number> {
  const { listQueue, getQueueItem, decideQueueItem, itemTruncation, shownBinding } = await import("./runtime/store.js");
  const { unlockApprover, approvalSigner } = await import("./runtime/approver.js");
  const { appendLog } = await import("./runtime/log.js");
  if (!(await humanAtKeyboard())) return 1;
  const pending = listQueue(l).items.filter((i) => i.status === "pending");
  const chosen = sub === "review" ? pending : p.positionals.map((x) => getQueueItem(l, x)).filter((x): x is NonNullable<typeof x> => x !== null && x.status === "pending");
  if (chosen.length === 0) {
    out(sub === "review" ? "Nothing is waiting for review." : `No pending queue item among: ${p.positionals.join(" ")}. Run: launchsafe-firewall queue list`);
    return sub === "review" ? 0 : 1;
  }
  // Some ids matched and some did not: name each one that did not, so a mistyped id is not mistaken for done.
  if (sub !== "review") {
    for (const x of p.positionals) {
      const it = getQueueItem(l, x);
      if (it === null || it.status !== "pending") out(`No pending item for: ${x}`);
    }
  }
  let signer: ReturnType<typeof approvalSigner> | undefined;
  let stateSigner: ((session: string, fields: readonly string[]) => string) | undefined;
  let learnSigner: ((fields: Parameters<typeof import("./runtime/approver.js").signLearned>[1]) => string) | undefined;
  let learnSeal: import("./runtime/learned.js").LearnedSealer | undefined;
  if (sub !== "reject") {
    const priv = unlockApprover(l, await (learnedOverrides.readSecret ?? readSecret)("Approval passphrase: "));
    const { signLearned, learnedSealer } = await import("./runtime/approver.js");
    learnSigner = (fields) => signLearned(priv, fields);
    learnSeal = learnedSealer(priv);
    signer = approvalSigner(priv);
    const { signStateChange } = await import("./runtime/approver.js");
    stateSigner = (session, fields) => signStateChange(priv, "scope-widen", session, fields);
  }
  // Tests calling main() in-process script the answers (learnedOverrides.ask); a person types them.
  const rl = learnedOverrides.ask === undefined ? createInterface({ input: process.stdin, output: process.stdout }) : null;
  const ask = learnedOverrides.ask ?? ((q: string): Promise<string> => (rl as NonNullable<typeof rl>).question(q));
  try {
    for (const it of chosen) {
      const shownAs = shownBinding(it);
      out(`\n${safeLine(it.id)}  ${it.kind === "proposal" ? "proposed change" : "needs approval"}  ${safeLine(it.tool)}\n${it.reasons.map((r) => `  - ${safeLine(r)}`).join("\n")}`);
      // I3: everything the approval lets run is shown, and anything cut (when stored or here) is said, with how much.
      const cut = [...itemTruncation(it)];
      const shown = (text: string, what: string): string => {
        if (text.length <= SHOW_CHARS) return text;
        cut.push(`${what} (${text.length - SHOW_CHARS} more characters)`);
        return `${text.slice(0, SHOW_CHARS)}… [${text.length - SHOW_CHARS} more characters]`;
      };
      if (it.proposal !== undefined) out(`  Change to ${it.proposal.target}:\n${shown(it.proposal.change, "the change").split("\n").map((x) => `    ${x}`).join("\n")}`);
      else out(`  Input: ${shown(String(JSON.stringify(it.input)), "the input")}`);
      if (Array.isArray(it.parts) && it.parts.length > 0) {
        out(`  Approving lets all ${it.parts.length} parts run, as a whole:`);
        it.parts.forEach((x, i) => {
          out(`    ${i + 1}. ${safeLine(x.tool)} ${safeLine(x.target)}${x.held === true ? " (held)" : ""}`);
          out(shown(x.change, `part ${i + 1}`).split("\n").map((y) => `       ${y}`).join("\n"));
        });
      }
      if (cut.length > 0) out(`  Not shown in full: ${cut.join("; ")}.`);
      const refuseCut = cut.length > 0 && !flag(p, "--i-saw-truncated");
      const refused = (): void => out(`  Not approved: parts of this action are not shown (above). Look at it with "launchsafe-firewall queue show ${it.id} --json", then approve with --i-saw-truncated if you still want it to run.`);
      if (sub === "approve" && refuseCut) {
        refused();
        continue;
      }
      let decision: string = sub;
      // Fewer prompts: "never in this project" for any held action, "always in this project" only where offered.
      const choice = sub === "review" ? await learnChoice(l, it) : null;
      if (choice !== null && !choice.ready) out(`  Always in this project: ${choice.note}`);
      const extra = choice === null ? "" : ` / [n]ever in this project${choice.ready ? " / [p] approve, and always in this project" : ""}`;
      if (sub === "review") decision = (await ask(`  [a]pprove once / [r]eject / [s]kip${extra}: `)).trim().toLowerCase();
      else decision = (await ask(`  ${sub === "approve" ? "Allow this exact action once" : "Reject it"}? Type "yes": `)).trim().toLowerCase() === "yes" ? sub : "s";
      if (refuseCut && (decision === "a" || decision === "approve" || decision === "p")) {
        refused();
        continue;
      }
      if (decision === "p" && choice?.ready === true && learnSigner !== undefined) {
        // The scope, restated, and a typed yes: "always" outlives this item.
        out(`  Always allow this exact action of ${safeLine(choice.cand.tool)} in ${safeLine(choice.cand.project)}, in attended sessions that have read no outside content and hold no private data.`);
        if ((await ask('  Approve once now, and always in this project? Type "yes": ')).trim().toLowerCase() !== "yes") {
          out("  Skipped.");
          continue;
        }
        decideQueueItem(l, it.id, "approved", signer, { shown: shownAs });
        appendLog(l, { type: "approval", queue: it.id, session: it.sessionId, action: it.actionHash });
        await saveChoice(l, choice, "allow", learnSigner, learnSeal);
        out(`  Approved once, and always allowed in this project from now on (${choice.code}; undo: launchsafe-firewall allow remove ${choice.code}). Ask the agent to try again.`);
        continue;
      }
      if (decision === "n" && choice !== null) {
        decideQueueItem(l, it.id, "rejected");
        appendLog(l, { type: "rejection", queue: it.id, session: it.sessionId, action: it.actionHash });
        await saveChoice(l, choice, "never", learnSigner, learnSeal);
        out(`  Rejected, and never allowed in this project from now on (${choice.code}; undo: launchsafe-firewall allow remove ${choice.code}).`);
        continue;
      }
      if (decision === "a" || decision === "approve") {
        decideQueueItem(l, it.id, "approved", signer, { shown: shownAs });
        appendLog(l, { type: "approval", queue: it.id, session: it.sessionId, action: it.actionHash });
        out("  Approved once. Ask the agent to try again.");
        if (stateSigner !== undefined) await offerWiden(l, it, stateSigner, ask);
      } else if (decision === "r" || decision === "reject") {
        decideQueueItem(l, it.id, "rejected");
        appendLog(l, { type: "rejection", queue: it.id, session: it.sessionId, action: it.actionHash });
        out("  Rejected.");
      } else out("  Skipped.");
    }
  } finally {
    rl?.close();
  }
  return 0;
}

/** What `queue review` can offer for a held item's "always" and "never in this project" (null: nothing is known about it). */
interface LearnChoice {
  code: string;
  ready: boolean;
  note: string;
  cand: import("./runtime/learned.js").Candidate;
}

async function learnChoice(l: Layout, it: import("./runtime/store.js").QueueItem): Promise<LearnChoice | null> {
  if (it.learn === undefined) return null;
  const { getCandidate, projectId } = await import("./runtime/learned.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const { learnedPolicy } = await import("./policy-learned.js");
  const { rulesEligibility, learnKey } = await import("./engine/learn.js");
  const cand = getCandidate(l, it.learn);
  if (cand === null) return null;
  // The item must be this candidate's action in this candidate's project: never sign a choice for anything else.
  const sameAction = learnKey({ tool: it.tool, input: (typeof it.input === "object" && it.input !== null ? it.input : {}) as Record<string, unknown> }) === cand.key;
  const sameProject = it.projectDir !== undefined && projectId(it.projectDir) === cand.project;
  if (!sameProject) return null;
  const lp = learnedPolicy(loadPolicy(l, [cand.project]).config);
  const byRules = rulesEligibility(cand.rules);
  // Approving this item counts as one more approval.
  const ready = sameAction && lp.enabled && cand.eligible && cand.identity !== null && byRules.eligible && cand.approved + 1 >= lp.proposeAfter;
  const note = !lp.enabled ? "switched off by your policy (learnedAllows.enabled)" : !byRules.eligible ? `not offered, because ${byRules.why}` : !cand.eligible || cand.identity === null ? `not offered, because ${safeLine(cand.why ?? "it is not a low-risk action")}` : !sameAction ? "not offered here (the held item differs from the action counted); use launchsafe-firewall allow add after the next approval" : `offered after you approve it ${lp.proposeAfter} times here (so far ${cand.approved})`;
  return { code: cand.code, ready, note, cand };
}

/** Stores "always" (signed; the caller holds the unlocked key) or "never" for a held item's action, and logs it. */
async function saveChoice(l: Layout, c: LearnChoice, kind: "allow" | "never", sign: ((fields: Parameters<typeof import("./runtime/approver.js").signLearned>[1]) => string) | undefined, seal?: import("./runtime/learned.js").LearnedSealer): Promise<void> {
  const { saveEntry } = await import("./runtime/learned.js");
  const { appendLog } = await import("./runtime/log.js");
  const createdAt = new Date().toISOString();
  const identity = kind === "allow" ? c.cand.identity : "";
  if (identity === null) throw new Error("this action has no tool identity, so it cannot be always allowed");
  // M1: the rules are signed with the choice (learned message v3), and the whole set is sealed.
  const fields = { kind, id: c.code, project: c.cand.project, key: c.cand.key, identity, tool: c.cand.tool, createdAt, rules: c.cand.rules };
  const sig = sign !== undefined ? sign(fields) : undefined;
  if (kind === "allow" && sig === undefined) throw new Error("always in this project needs the approval passphrase");
  const replaced = saveEntry(l, { version: 1, ...fields, summary: c.cand.summary, rules: c.cand.rules, approvals: c.cand.approved + (kind === "allow" ? 1 : 0), ...(sig !== undefined ? { sig } : {}) }, seal !== undefined ? { seal } : {});
  if (replaced !== null && replaced.kind !== kind) out(`  This replaced your "${replaced.kind === "allow" ? "always" : "never"}" choice for it.`);
  appendLog(l, { type: "learned_choice", change: kind === "allow" ? "always" : "never", id: c.code, project: c.cand.project, key: c.cand.key, identity, tool: c.cand.tool, rules: c.cand.rules, ...(replaced !== null ? { replaced: replaced.kind } : {}), ...(sig !== undefined ? { sig } : {}) });
}

/**
 * After approving a FW-SCOPE item, offer to widen that session's task scope by what the action
 * needed (the default is no). Yes appends a widening signed with the key already unlocked.
 */
async function offerWiden(l: Layout, it: import("./runtime/store.js").QueueItem, sign: (session: string, fields: readonly string[]) => string, ask: (q: string) => Promise<string>): Promise<void> {
  if (!it.rules.includes("FW-SCOPE")) return;
  const { widenScope } = await import("./runtime/scope.js");
  const { appendLog } = await import("./runtime/log.js");
  for (const w of it.scopeWiden ?? []) {
    const answer = (await ask(`  Widen the task scope of this session to include ${w.kind} ${w.value}? [y/N]: `)).trim().toLowerCase();
    if (answer !== "y" && answer !== "yes") continue;
    const id = widenScope(l, it.sessionId, w, (fields) => sign(it.sessionId, fields));
    appendLog(l, { type: "scope_widen", session: it.sessionId, kind: w.kind, value: w.value, id });
    out(`  Task scope widened (${id}).`);
  }
}

async function queueList(p: Ok, l: Layout): Promise<number> {
  const { listQueue } = await import("./runtime/store.js");
  const { items, corrupt } = listQueue(l);
  const pending = items.filter((i) => i.status === "pending");
  if (flag(p, "--json")) out(JSON.stringify(pending, null, 2));
  else {
    const { formatQueue, terminalWidth } = await import("./runtime/report.js");
    out(formatQueue(pending, { width: terminalWidth(process.stdout.columns) }));
  }
  if (corrupt.length > 0) err(`Unreadable queue files: ${corrupt.join(", ")}`);
  return 0;
}

async function pinsList(p: Ok, l: Layout): Promise<number> {
  const { loadPins, parsePins, pinsPath } = await import("./runtime/pins.js");
  const { readText } = await import("./runtime/fsutil.js");
  // Read only: a corrupt file is reported, not moved (the hook moves it aside).
  const text = readText(pinsPath(l));
  const pins = text === null ? loadPins(l).pins : parsePins(text);
  if (pins === null) {
    err(`${pinsPath(l)} is unreadable; the next session moves it aside and pins every server again.`);
    return 1;
  }
  if (flag(p, "--json")) {
    out(JSON.stringify(pins, null, 2));
    return 0;
  }
  const servers = Object.values(pins.servers).sort((a, b) => (a.key < b.key ? -1 : 1));
  if (servers.length === 0) out("No MCP server is pinned yet (servers are pinned when a session first sees them).");
  for (const s of servers) out(`${s.name}  (${s.source}${s.file !== undefined ? `, ${s.file}` : ""})  pinned ${s.pinnedAt.slice(0, 10)} by ${s.pinnedBy === "person" ? "you" : "first use"}; launch ${s.launch.pin}; ${s.tools.length} tool(s), ${Object.keys(s.descriptions).length} description(s)`);
  if (pins.pending.length > 0) {
    out(`\nWaiting for your review (${pins.pending.length}):`);
    for (const c of pins.pending) out(`  ${c.name}  ${c.kind.replace("_", " ")}  ${c.detail} (last seen ${c.lastSeen.slice(0, 16).replace("T", " ")})`);
    out(`\nAfter checking a change, accept it in your own terminal: launchsafe-firewall pins accept <server>`);
  }
  return 0;
}

async function canaryList(p: Ok, l: Layout): Promise<number> {
  const { loadRegistry } = await import("./runtime/canaries.js");
  const { existsSync } = await import("node:fs");
  const reg = loadRegistry(l);
  if (!reg.ok) {
    err(`The canary registry is damaged: ${reg.error}. Run "launchsafe-firewall canary remove --all", then "launchsafe-firewall canary plant".`);
    return 1;
  }
  // The decoy's value is not shown: it is not a secret, but nothing needs to print it.
  const rows = reg.canaries.map((c) => ({ id: c.id, kind: c.kind, path: c.path, present: existsSync(c.path), plantedAt: c.plantedAt, ...(c.workspace !== undefined ? { workspace: c.workspace } : {}) }));
  if (flag(p, "--json")) out(JSON.stringify(rows, null, 2));
  else if (rows.length === 0) out('No decoys are planted. Plant some with "launchsafe-firewall canary plant".');
  else for (const r of rows) out(`${r.id}  ${r.kind.padEnd(5)}  ${r.present ? "present" : "MISSING"}  ${r.path}`);
  return 0;
}

async function rolloutStatus(p: Ok, l: Layout): Promise<number> {
  const { loadPolicy } = await import("./runtime/config.js");
  const { enforcedCoreLines, pinnedWatchKey, watchState } = await import("./runtime/rollout.js");
  const { WATCH_ENFORCED_GROUPS } = await import("./policy-rollout.js");
  const { homedir } = await import("node:os");
  const st = watchState(l, loadPolicy(l, [process.cwd()]), pinnedWatchKey(l, homedir()));
  if (flag(p, "--json")) {
    out(JSON.stringify({ mode: st.active ? "watch" : "enforce", requested: st.requested, layer: st.layer, ...(st.path !== undefined ? { path: st.path } : {}), ...(st.grant !== undefined ? { grant: { id: st.grant.id, at: st.grant.at, until: st.grant.until } } : {}), ...(st.problem !== undefined ? { problem: st.problem } : {}), alwaysEnforced: WATCH_ENFORCED_GROUPS }, null, 2));
    return 0;
  }
  const from = st.layer === "default" ? "the default" : `the ${st.layer} policy${st.path !== undefined ? ` (${st.path})` : ""}`;
  if (st.active) {
    out(`Rollout mode: watch, set by ${from}${st.grant !== undefined ? `, grant ${st.grant.id} from ${st.grant.at} until ${st.grant.until}` : ""}.`);
    out("Risky actions are logged and allowed. Still enforced in watch mode:");
    for (const line of enforcedCoreLines()) out(`  ${line}`);
    out("What enforcing would have done: launchsafe-firewall rollout report");
  } else {
    out(`Rollout mode: enforce (${from}).`);
    if (st.problem !== undefined) out(`Watch mode is requested but not in effect: ${st.problem}`);
  }
  return 0;
}

async function policyShow(_p: Ok, l: Layout): Promise<number> {
  const { loadPolicy } = await import("./runtime/config.js");
  const { readEntries, readNevers, projectId, entrySigned } = await import("./runtime/learned.js");
  const { trustedApproverKey } = await import("./hook/pipeline.js");
  const cfg = loadPolicy(l, [process.cwd()]).config;
  // The person's learned choices for this project are part of what is in effect, so they are shown here too
  // (they live in the firewall's home, signed, never in a policy file; manage them with "allow").
  const project = projectId(process.cwd());
  const key = trustedApproverKey(l, process.env);
  const read = readEntries(l);
  const all = [...read.entries, ...readNevers(l).entries.filter((n) => !read.entries.some((e) => e.project === n.project && e.key === n.key))];
  const choices = all.filter((e) => e.project === project).map((e) => ({ id: e.id, choice: e.kind === "allow" ? "always" : "never", tool: e.tool, summary: e.summary, rules: e.rules, createdAt: e.createdAt, ...(e.kind === "allow" ? { applies: !read.damaged && entrySigned(e, key) } : {}) }));
  out(JSON.stringify(choices.length > 0 ? { ...cfg, learnedChoices: { project, note: "not a policy key: stored in the firewall's home; launchsafe-firewall allow list / allow remove <id>", choices } } : cfg, null, 2));
  return 0;
}

/**
 * humanAtKeyboard for a command whose output may be piped (log export --out -): a terminal on standard input,
 * and not a descendant of a Claude Code session. Like humanAtKeyboard it is a second line behind the hook,
 * which is the real gate (an agent can fake a terminal; its tool call running the command is FW-TAMPER).
 */
async function personAtTerminal(name: string): Promise<boolean> {
  if (keyboardCheck !== null) return keyboardCheck();
  const { agentLaunch } = await import("./runtime/approver.js");
  if (process.stdin.isTTY !== true) {
    err(`launchsafe-firewall ${name} runs only for a person at a terminal (standard input is not one).`);
    return false;
  }
  const why = agentLaunch();
  if (why === "unknown") {
    err(unreadAncestry(`launchsafe-firewall ${name}`));
    return false;
  }
  if (why !== null) {
    err(`launchsafe-firewall ${name} was started from inside a coding agent's session (Claude Code, Codex, Gemini CLI or Cursor). Run it in a terminal of your own.`);
    return false;
  }
  return true;
}

/** log verify <bundle>: the standalone verifier (src/logbundle/verify.ts); reads only the files named. */
async function verifyBundleCommand(p: Ok, bundle: string): Promise<number> {
  const { verifyBundle, formatResult, resolvePin, statusExit } = await import("./logbundle/verify.js");
  let text: string;
  const keys: string[] = [];
  const anchors: string[] = [];
  try {
    text = readFileSync(bundle, "utf8");
    // A fingerprint, or only the PEM public-key block of a file: nothing else of a file is used or printed.
    for (const k of p.lists?.get("--key") ?? []) keys.push(resolvePin(k));
    for (const a of p.lists?.get("--anchor") ?? []) anchors.push(readFileSync(a, "utf8"));
  } catch (e) {
    err(`launchsafe-firewall log verify: ${(e as Error).message}`);
    return 1;
  }
  const r = verifyBundle(text, { keys, anchors, allowUnpinned: flag(p, "--no-pin") });
  out(flag(p, "--json") ? JSON.stringify(r, null, 2) : formatResult(r));
  return statusExit(r.status);
}

async function logTail(p: Ok, l: Layout): Promise<number> {
  const { tailLog } = await import("./runtime/log.js");
  const n = Number(p.positionals[0] ?? "20");
  for (const e of tailLog(l, Number.isFinite(n) ? n : 20)) out(`${e.seq} ${e.ts} ${JSON.stringify(e.event)}`);
  return 0;
}

/** G5: pin the key in every installed hook command and say what happened. */
async function repinMessage(l: Layout, lead: string): Promise<string> {
  const { repinApprover: repin, readRecords } = await import("./runtime/install.js");
  const { adapterFor } = await import("./adapters/index.js");
  const repinApprover = (x: Layout): ReturnType<typeof repin> => repin(x, (id) => adapterFor(id).settings);
  let recorded = 0;
  try {
    recorded = readRecords(l).length;
  } catch {
    recorded = 0;
  }
  if (recorded === 0) return `${lead} The firewall is not installed yet: run "launchsafe-firewall install" and the hook will pin this key.`;
  const r = repinApprover(l);
  const lines = [lead, r.updated.length > 0 ? `The hook now pins this key in ${r.updated.join(", ")}.` : "The hook already pins this key."];
  for (const k of r.skipped) lines.push(`Could not update ${k.path} (${k.reason}); run "launchsafe-firewall install" for that file.`);
  return lines.join("\n");
}

async function approverStatus(_p: Ok, l: Layout): Promise<number> {
  const { approverPublicKey, approverKdfWeak } = await import("./runtime/approver.js");
  out(approverPublicKey(l) === null ? "No approval passphrase is set." : "An approval passphrase is set. Approvals and uninstall need it.");
  // I4: an older key file is re-encrypted with the stronger key derivation the next time the passphrase unlocks it.
  try {
    if (approverKdfWeak(l)) out("Its key file uses the older, weaker key derivation; the next approval (or any command that asks for the passphrase) re-encrypts it with the current one. The key itself stays the same.");
  } catch {
    out("Its key file is damaged. Run: launchsafe-firewall doctor");
  }
  return 0;
}

/** The old `check`: judge one action read as JSON on stdin. */
async function scopeShow(p: Ok, l: Layout): Promise<number> {
  const { loadState, recentSessions } = await import("./runtime/store.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const { formatScope } = await import("./runtime/scope.js");
  const { trustedApproverKey } = await import("./hook/claude.js");
  const session = p.positionals[0] ?? recentSessions(l, 1)[0]?.id;
  if (session === undefined) {
    out("No recent session. Give a session id: launchsafe-firewall scope show <session>");
    return 0;
  }
  const state = loadState(l, session, trustedApproverKey(l, process.env));
  const cfg = loadPolicy(l, [process.cwd()]).config;
  if (flag(p, "--json")) out(JSON.stringify({ session, mode: cfg.taskScope.mode, scope: state.scope, widened: state.scopeWidenings }, null, 2));
  else out(formatScope(session, state, cfg));
  return 0;
}

async function capsShow(p: Ok, l: Layout): Promise<number> {
  const { loadState, recentSessions } = await import("./runtime/store.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const { capStatus } = await import("./runtime/caps.js");
  const { trustedApproverKey } = await import("./hook/claude.js");
  const key = trustedApproverKey(l, process.env);
  const id = opt(p, "--session") ?? recentSessions(l, 1)[0]?.id;
  const session = id !== undefined ? { id, state: loadState(l, id, key) } : null;
  const cfg = loadPolicy(l, [process.cwd()]).config;
  const s = capStatus(l, cfg, session, key);
  out(flag(p, "--json") ? JSON.stringify(s.json, null, 2) : s.text);
  return 0;
}

async function checkStdin(l: Layout): Promise<number> {
  const { decide } = await import("./engine/decide.js");
  const { foldEvents } = await import("./engine/state.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const { buildContext } = await import("./runtime/context.js");
  const { scopeFromPrompt } = await import("./engine/scope.js");
  const { statKind } = await import("./runtime/scope.js");
  const { createHash } = await import("node:crypto");
  let raw: string;
  try {
    raw = readStdin();
  } catch (e) {
    err(`LaunchSafe Firewall did not judge the request: ${(e as Error).message}.`);
    return 1;
  }
  const req = JSON.parse(raw) as { tool: string; input: Record<string, unknown>; untrusted?: boolean; unattended?: boolean; prompt?: string; cwd?: string };
  const cwd = req.cwd ?? process.cwd();
  const pol = loadPolicy(l, [cwd]);
  const { ctx } = buildContext({ l, cfg: pol.config, basics: { sessionId: "check", cwd }, env: { ...process.env, CLAUDE_PROJECT_DIR: cwd }, detectNonInteractive: () => false });
  if (req.unattended === true) ctx.interactive = false;
  // With a prompt, the decision is made under the scope that prompt would set (in the policy's mode).
  const events: import("./types.js").StateEvent[] = req.untrusted === true ? [{ type: "taint", source: "check --untrusted" }] : [];
  const scope = typeof req.prompt === "string" && pol.config.taskScope.mode !== "off" ? scopeFromPrompt(req.prompt, createHash("sha256").update(req.prompt).digest("hex"), ctx, { stat: statKind }) : null;
  if (scope !== null) events.push({ type: "scope", scope });
  // The person's "never" choices for this project apply here too ("always" choices never do: no session, no person).
  const { loadNevers, projectId } = await import("./runtime/learned.js");
  const learned = { allows: new Map<string, string>(), nevers: loadNevers(l, projectId(cwd)), identity: null };
  const d = decide({ action: { tool: req.tool, input: req.input }, state: foldEvents(events), config: pol.config, ctx, learned });
  const scopeOut = scope === null ? {} : { taskScope: { mode: pol.config.taskScope.mode, scope: { ...scope, prompt: undefined }, effect: d.scope ?? null } };
  out(JSON.stringify({ verdict: d.verdict, rules: d.rules, reasons: d.reasons, effects: d.effects.map((e) => ({ class: e.cls, target: e.target, detail: e.detail })), findings: d.findings, ...scopeOut }, null, 2));
  return 0;
}

type UpdateFn = typeof import("./runtime/intel.js").runUpdate;

async function runUpdateCommand(l: Layout, o: Parameters<UpdateFn>[1], run: UpdateFn): Promise<number> {
  out("Downloading malicious-package data. This is the only command that downloads data without a prompt (doctor --fix offers the same download after you confirm); decisions make no network calls unless you pair a phone (experimental), and run is a network proxy.");
  try {
    const r = await run(l.home, { ...o, log: (line) => out(`  ${line}`) });
    out(`Updated: ${r.manifest.sources.reduce((a, s) => a + s.entries, 0)} listed package name(s) across ${r.manifest.sources.map((s) => s.eco).join(", ")} (${r.path}).`);
    return 0;
  } catch (e) {
    err(`launchsafe-firewall update failed: ${(e as Error).message}. The previous malicious-package data (if any) is still in use.`);
    return 1;
  }
}

/**
 * `doctor --fix`: the sandbox profile and the approval-key pin (settings changes: the approval
 * passphrase first, then the diff, then "yes"), then the package fixes (package cooldowns in user config,
 * the malicious-package data). With --dry-run every change is printed and nothing is asked or written.
 */
/** `doctor --repair-state`: rebuild a damaged install.json from the agent files that hold the firewall's hooks. */
async function repairInstallState(l: Layout, project: string): Promise<number> {
  const { repairState } = await import("./runtime/install.js");
  const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
  const { adapterFor } = await import("./adapters/index.js");
  const { AGENT_IDS } = await import("./adapters/types.js");
  const { homedir } = await import("node:os");
  if (!(await humanAtKeyboard())) return 1;
  if (approverPublicKey(l) !== null) unlockApprover(l, await readSecret("Approval passphrase: "));
  const r = repairState(l, project, VERSION, AGENT_IDS.map((id) => ({ id, settings: adapterFor(id).settings })), homedir());
  if (r.ok) {
    out(`${l.home}/install.json is readable: nothing to repair.`);
    return 0;
  }
  out(`The damaged install record was moved to ${r.movedTo ?? ""} and rebuilt from the settings files that hold the firewall's hooks:`);
  for (const x of r.rebuilt) out(`  ${x.agent} (${x.scope}): ${x.path}${x.backup === "" ? " (no backup of the original was found, so --restore-backup can only remove the hooks)" : `, original backup ${x.backup}`}`);
  if (r.rebuilt.length === 0) out("  none found: the firewall's hooks are not in any settings file it looked at (each agent's user file, and this project's).");
  out('Run "launchsafe-firewall doctor" to check the result.');
  return 0;
}

async function doctorFix(l: Layout, project: string, checks: { name: string; status: string; detail: string }[], o: { scope: "user" | "project" | "local"; dryRun: boolean }): Promise<number> {
  const { planCooldownFixes, applyCooldownFix } = await import("./runtime/cooldown.js");
  const { planSandboxFix, runSandboxFix, describePlan } = await import("./runtime/sandbox.js");
  const { loadPolicy } = await import("./runtime/config.js");
  const { claudeVersion } = await import("./runtime/doctor.js");
  const { homedir } = await import("node:os");
  const home = homedir();
  const plan = planSandboxFix(l, project, loadPolicy(l, [project]).config, { scope: o.scope, home, platform: process.platform, claudeVersion: claudeVersion(home) });
  const unpinned = checks.some((c) => c.name === "approval passphrase" && /set, but not pinned/.test(c.detail));
  if (o.dryRun) {
    describePlan(plan, out);
    if (plan.refused !== undefined) out(`  Refused: ${plan.refused}`);
    if (unpinned) out('\nThe hook command does not pin your approval key: doctor --fix would pin it (same as running "launchsafe-firewall install" again).');
    for (const fix of planCooldownFixes(project, { home, env: process.env })) out(`\nSet a release-age cooldown for ${fix.manager} in your user config (never in the project):\n${fix.diff.map((x) => `  ${x}`).join("\n")}`);
    out("\nDry run: nothing was written.");
    return 0;
  }
  if (!(await humanAtKeyboard())) return 1;
  // One passphrase per run, read before the line reader starts (it must not echo): the sandbox profile
  // and the key pin are both settings changes.
  const { approverPublicKey } = await import("./runtime/approver.js");
  const needsPassphrase = approverPublicKey(l) !== null && ((plan.refused === undefined && (plan.changed || plan.rerecord)) || unpinned);
  const typed = needsPassphrase ? await readSecret("Approval passphrase (for the settings changes below): ") : "";
  const passphrase = async (): Promise<string> => typed;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const confirm = async (q: string): Promise<boolean> => (await rl.question(q)).trim().toLowerCase() === "yes";
  try {
    await runSandboxFix(l, plan, { passphrase, confirm, say: out });
    if (unpinned) {
      const { unlockApprover } = await import("./runtime/approver.js");
      out("\nThe hook command does not pin your approval key, so approvals fall back to the key on disk.");
      try {
        unlockApprover(l, await passphrase());
        if (await confirm('  Pin it in the hook command now? Type "yes": ')) out(await repinMessage(l, " "));
        else out("  Skipped.");
      } catch (e) {
        out(`  ${(e as Error).message}. Nothing was written.`);
      }
    }
    for (const fix of planCooldownFixes(project, { home: homedir(), env: process.env })) {
      out(`\nSet a release-age cooldown for ${fix.manager} in your user config (never in the project):\n${fix.diff.map((x) => `  ${x}`).join("\n")}`);
      if (!(await confirm('  Write this? Type "yes": '))) {
        out("  Skipped.");
        continue;
      }
      const backup = applyCooldownFix(fix, l.backups);
      out(`  Written: ${fix.path}${backup !== null ? ` (backup: ${backup})` : ""}`);
    }
    const intel = checks.find((c) => c.name === "malicious-package data");
    if (intel !== undefined && intel.status !== "ok" && (await rl.question('\nDownload the malicious-package data now (network)? Type "yes": ')).trim().toLowerCase() === "yes") {
      const { runUpdate } = await import("./runtime/intel.js");
      rl.close();
      return runUpdateCommand(l, {}, runUpdate);
    }
  } finally {
    rl.close();
  }
  return 0;
}

/**
 * The hook's code. The build also writes it as one file (scripts/bundle-hook.mjs): loading ~150 modules
 * one by one is a third of what each tool call costs. The bundle is used only when it is at least as new
 * as the modules it was made from, so a tsc run without the bundle step never leaves an old hook in use;
 * without it (no bundler, tests running src/) the modules load as before. A bundle that is there and
 * fails to load is an error like any other, and the hook fails closed (cli.ts).
 */
async function loadHook(): Promise<typeof import("./hook/claude.js")> {
  const bundle = new URL("./hook/bundle.js", import.meta.url);
  let fresh = false;
  try {
    fresh = statSync(bundle).mtimeMs >= statSync(new URL("./hook/claude.js", import.meta.url)).mtimeMs;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  return fresh ? ((await import(bundle.href)) as typeof import("./hook/claude.js")) : import("./hook/claude.js");
}

/** `install --browser`: the native messaging host manifest for the LaunchSafe extension (docs/browser-link.md). */
async function installBrowserLink(p: Ok, l: Layout): Promise<number> {
  const others = [...p.flags.keys()].filter((k) => !["--browser", "--extension-id", "--user-data-dir"].includes(k));
  if (others.length > 0) {
    err(`launchsafe-firewall install: --browser cannot be combined with ${others.join(", ")}. Run "launchsafe-firewall install --help".`);
    return EXIT_USAGE;
  }
  const { installHost, browserLabel } = await import("./runtime/native/browsers.js");
  const browser = opt(p, "--browser") as import("./runtime/native/browsers.js").Browser;
  const ids = p.lists?.get("--extension-id") ?? [];
  const userDataDir = opt(p, "--user-data-dir");
  const r = installHost(l, browser, ids, userDataDir !== undefined ? { userDataDir } : {});
  const { loadKey } = await import("./runtime/log.js");
  loadKey(l);
  out(`${r.changed ? "Installed" : "Already installed"} the browser link for ${browserLabel(browser)}: ${r.manifest}\nIt starts ${r.launcher} for the extension ${ids.join(", ")} only.\nNext: in the extension's side panel, turn on "Link to the local firewall", then run "launchsafe-firewall doctor".`);
  const { approverPublicKey } = await import("./runtime/approver.js");
  if (approverPublicKey(l) === null) out('No approval passphrase is set, so the browser cannot send approvals to the firewall. In your own terminal run "launchsafe-firewall approver init", then this install again.');
  return 0;
}

/** CLI audit M1: a session-scoped caps command names a session the firewall has a record of. */
export async function unknownSession(l: Layout, session: string | undefined): Promise<string | null> {
  if (session === undefined) return null;
  const { sessionFile } = await import("./runtime/store.js");
  const { countersFile } = await import("./runtime/counters.js");
  const { existsSync } = await import("node:fs");
  if (existsSync(sessionFile(l, session)) || existsSync(countersFile(l, session))) return null;
  return `launchsafe-firewall caps: no session ${session} is recorded (check the id with "launchsafe-firewall status"). Nothing was changed.`;
}

/**
 * CLI audit M1: the hooks verify a raise against the key pinned in their command; a passphrase that unlocks another
 * key (rotated without reinstalling) would write a raise the hooks ignore. Refused before anything is written.
 */
export async function keyMatchesPins(l: Layout, priv: import("node:crypto").KeyObject): Promise<boolean> {
  const { publicKeyOf } = await import("./runtime/approver.js");
  const { pinnedApproverKeys } = await import("./runtime/install.js");
  const mine = publicKeyOf(priv);
  if (pinnedApproverKeys(l, process.env).some((k) => k !== mine)) {
    err('The hooks pin a different approval key than the one your passphrase unlocks (rotated without reinstalling?), so they would ignore this. Run "launchsafe-firewall install" again, then try again. Nothing was changed.');
    return false;
  }
  return true;
}

export const HANDLERS: Record<string, Handler> = {
  async "native-host"(p, l) {
    const { runNativeHost } = await import("./runtime/native/host.js");
    // Chrome reads only our frames on stdout: nothing else may be written there.
    return runNativeHost(process.stdin, { layout: l, env: process.env, origin: p.positionals[0], version: VERSION, write: (frame) => void writeSync(1, frame) });
  },
  async hook(p, l) {
    // trustedHome comes with the hook bundle, so the hook process loads no extra module for it.
    const { runHook, trustedHome: hookHome } = await loadHook();
    const agent = (opt(p, "--agent") ?? "claude") as "claude" | "codex" | "gemini" | "cursor";
    let raw: string;
    try {
      raw = readStdin();
    } catch (e) {
      // Without the whole event the action cannot be judged: block it (every supported agent honors exit 2).
      err(`LaunchSafe Firewall could not read the hook input and blocked the action: ${(e as Error).message}.`);
      return 2;
    }
    const record = opt(p, "--record");
    if (record !== undefined) {
      const { recordEvent } = await import("./runtime/record.js");
      try {
        recordEvent(record, raw, process.env);
      } catch (e) {
        err(`LaunchSafe Firewall could not record the hook event: ${(e as Error).message}`);
      }
    }
    // I1: the home comes from the user database, not HOME; with no data directory pinned (a managed command pins it
    // empty), the default one is derived from that home too. A HOME that differs is refused in runHook (FW-TAMPER).
    const th = hookHome(process.env);
    const fwHome = process.env.LAUNCHSAFE_FIREWALL_HOME;
    const hl = fwHome === undefined || fwHome === "" ? layout(resolve(th.home, ".launchsafe-firewall")) : l;
    const { hookStartedAt } = await import("./hook/deadline.js");
    const res = runHook(raw, { env: process.env, layout: hl, agent, home: th.home, startedAt: hookStartedAt(process.env, process.uptime()), ...(th.tamper !== null ? { homeTamper: th.tamper } : {}) });
    if (res.stdout !== "") writeSync(1, res.stdout);
    if (res.stderr !== "") err(res.stderr);
    return res.exitCode;
  },
  async install(p, l) {
    const { install, hookCommand, assertSupportedPlatform } = await import("./runtime/install.js");
    const { adapterFor } = await import("./adapters/index.js");
    assertSupportedPlatform();
    if (opt(p, "--browser") !== undefined) return installBrowserLink(p, l);
    if (opt(p, "--extension-id") !== undefined || opt(p, "--user-data-dir") !== undefined) {
      err(`launchsafe-firewall install: --extension-id and --user-data-dir only apply with --browser. Run "launchsafe-firewall install --help".`);
      return EXIT_USAGE;
    }
    const agent = (opt(p, "--agent") ?? "claude") as "claude" | "codex" | "gemini" | "cursor";
    const adapter = adapterFor(agent);
    if (flag(p, "--managed")) {
      const snippet = adapter.settings.managedSnippet(hookCommand(l, undefined, undefined, agent, { managed: true }), flag(p, "--lock-other-hooks"));
      if (flag(p, "--print")) {
        out(snippet.text);
        return 0;
      }
      // Item 8: never suggest overwriting an existing managed file: Claude Code reads drop-ins beside it.
      const dropIn = agent === "claude" ? join(dirname(snippet.path), "managed-settings.d", "50-launchsafe-firewall.json") : null;
      const how =
        dropIn !== null
          ? `For example, as a drop-in that leaves an existing managed-settings.json alone:\n  sudo mkdir -p "${dirname(dropIn)}" && launchsafe-firewall install --managed --print | sudo tee "${dropIn}" >/dev/null`
          : `If ${snippet.path} already exists, merge this into it by hand; only when it does not exist:\n  launchsafe-firewall install --managed --agent ${agent} --print | sudo tee "${snippet.path}" >/dev/null`;
      out(`Managed settings make the firewall's hooks impossible to switch off from ${adapter.settings.label}'s user or project settings files (not from command-line flags${agent === "gemini" || agent === "cursor" ? "; for Gemini CLI and Cursor this is a system-level install with no lock on other hooks, and Gemini CLI skips every hook in a folder it does not trust" : ""}).\nWrite this (needs administrator rights) to ${dropIn ?? snippet.path}, without replacing any existing managed settings:\n\n${snippet.text}\n\n${how}`);
      return 0;
    }
    if (flag(p, "--lock-other-hooks") || flag(p, "--print")) {
      err(`launchsafe-firewall install: --lock-other-hooks and --print only apply with --managed. Run "launchsafe-firewall install --help".`);
      return EXIT_USAGE;
    }
    const scope = (opt(p, "--scope") ?? "user") as "user" | "project" | "local";
    if (!adapter.settings.scopes.includes(scope)) {
      err(`launchsafe-firewall install: ${adapter.settings.label} has no ${scope} settings file (use --scope ${adapter.settings.scopes.join(" or ")}).`);
      return EXIT_USAGE;
    }
    const project = resolve(opt(p, "--project") ?? process.cwd());
    // Gemini CLI's seatbelt profile: checked before anything is written, so a refusal changes nothing.
    const seatbelt = opt(p, "--seatbelt") as import("./runtime/gemini-seatbelt.js").SeatbeltBase | undefined;
    let geminiBundle: string | null = null;
    if (seatbelt === undefined && opt(p, "--gemini-package") !== undefined) {
      err(`launchsafe-firewall install: --gemini-package only applies with --seatbelt. Run "launchsafe-firewall install --help".`);
      return EXIT_USAGE;
    }
    if (seatbelt !== undefined) {
      if (agent !== "gemini") {
        err(`launchsafe-firewall install: --seatbelt is for Gemini CLI's own sandbox (gemini -s): use it with --agent gemini.`);
        return EXIT_USAGE;
      }
      if (process.platform !== "darwin") {
        err("launchsafe-firewall install: --seatbelt writes a macOS seatbelt profile; Gemini CLI's -s uses one only on macOS.");
        return EXIT_USAGE;
      }
      const { findGeminiBundle } = await import("./runtime/gemini-seatbelt.js");
      const dir = opt(p, "--gemini-package");
      geminiBundle = findGeminiBundle(dir !== undefined ? { dir } : {});
      if (geminiBundle === null) {
        err(dir !== undefined ? `launchsafe-firewall install: no Gemini CLI seatbelt profiles in ${dir} (or its bundle/ directory).` : 'launchsafe-firewall install: Gemini CLI was not found on PATH, so its seatbelt profile cannot be copied. Give its package with --gemini-package DIR (for example "$(npm root -g)/@google/gemini-cli").');
        return 1;
      }
    }
    const { approverPublicKey, initApprover, launchedByAgent } = await import("./runtime/approver.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    const { homedir } = await import("node:os");
    // Refuse before asking for a passphrase, so a test never reaches the prompt with the real home.
    assertNotRealHome(adapter.settings.path(scope, project, homedir()));
    assertNotRealHome(l.home);
    if (approverPublicKey(l) === null && !flag(p, "--no-approver") && process.stdin.isTTY === true && process.stdout.isTTY === true && !launchedByAgent()) {
      out("Set an approval passphrase. You type it to approve a held action or to uninstall. Do not type it into the agent; the firewall never passes it to the agent.");
      initApprover(l, await newPassphrase());
    }
    const r = install(l, scope, project, VERSION, { agent, settings: adapter.settings });
    const { loadKey } = await import("./runtime/log.js");
    loadKey(l);
    out(`${r.changed ? "Installed" : "Already installed"} (${adapter.settings.label}): ${r.path}\nBackup of the original settings: ${r.backup}${r.linkedTo !== undefined ? `\n${r.path} is a symbolic link to ${r.linkedTo}: the hooks were written to that file and the link was kept.` : ""}${r.pinned ? "\nThe hook pins your approval key." : ""}${approverPublicKey(l) === null ? `\nNo approval passphrase is set, so held actions cannot be approved yet. In your own terminal run "launchsafe-firewall approver init", then "launchsafe-firewall install" again to pin it.` : ""}\nNext: run "launchsafe-firewall doctor".`);
    // The recommended install for a team, or wherever repositories someone else wrote are opened: a repository's
    // settings can switch user-level hooks off (in a claude -p run without the trust dialog); managed ones cannot.
    // Managed settings are read before a repository's or a user's own, so those cannot switch the hooks off. It does not
    // cover flags a CI job passes, and Codex's managed install has not been tested on a real machine (docs/agents/codex.md).
    const managedCaveat = agent === "codex" ? "; not yet tested on a real machine for Codex" : agent === "gemini" || agent === "cursor" ? "; for Gemini CLI and Cursor this is a system-level install with no lock on other hooks, and Gemini CLI skips every hook in a folder it does not trust" : "";
    out(`Recommended: a repository's own settings can switch user-level hooks off. Managed settings are applied before a repository's or a user's own, so those cannot switch the hooks off (needs admin rights; flags a CI job passes are not covered${managedCaveat}): launchsafe-firewall install --managed${agent === "claude" ? "" : ` --agent ${agent}`}${agent === "claude" || agent === "codex" ? " --lock-other-hooks" : ""}. Check any time with: launchsafe-firewall doctor --ci`);
    if (agent === "codex") out("Codex runs a hook only once it is trusted and skips it silently otherwise: install recorded the trust of these hooks in Codex's config.toml (backup kept). If you edit them by hand, run install again.");
    if (agent === "gemini") out("Gemini CLI skips every hook in a folder it does not trust: trust the folders you work in.");
    if (seatbelt !== undefined && geminiBundle !== null) {
      const { installSeatbelt, SEATBELT_PROFILE_NAME } = await import("./runtime/gemini-seatbelt.js");
      const sb = installSeatbelt(l, { base: seatbelt, bundle: geminiBundle });
      out(`${sb.changed ? "Wrote" : "Already up to date:"} ${sb.path}: Gemini CLI's ${seatbelt} profile (from ${geminiBundle}), plus write access to the firewall's state directories only.${sb.backup !== undefined ? `\nThe file that was there is saved as ${sb.backup}.` : ""}\nTo use it, export SEATBELT_PROFILE=${SEATBELT_PROFILE_NAME} in your shell profile and start Gemini CLI with -s. Run this again after updating Gemini CLI (doctor tells you when).`);
    } else if (agent === "gemini" && process.platform === "darwin") out("Under Gemini CLI's own sandbox (gemini -s) the firewall cannot save its state and blocks every action. To use -s, run install --agent gemini --seatbelt permissive-open.");
    if (agent === "cursor") out(scope === "project" ? "Cursor runs a project's hooks only in a trusted workspace, and its cloud agents run them too, where this machine's paths do not exist (the hooks fail closed there). Prefer --scope user unless you know you want this." : "Cursor loads ~/.cursor/hooks.json in every workspace and reloads it on save; nothing else to enable.");
    // Offer workspace decoys (a yes/no prompt, only for a person in a terminal, never in tests or agents).
    if (process.stdin.isTTY === true && process.stdout.isTTY === true && !launchedByAgent()) {
      const { offerDecoysAtInstall } = await import("./runtime/canaries.js");
      const { loadPolicy } = await import("./runtime/config.js");
      const cfg = loadPolicy(l, [process.cwd()]).config.canaries;
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        await offerDecoysAtInstall(l, { cwd: process.cwd(), enabled: cfg.enabled, offer: cfg.offerAtInstall, homeDecoys: cfg.homeDecoys, interactive: true, ask: async (q) => /^y(es)?$/i.test((await rl.question(q)).trim()), say: out });
      } finally {
        rl.close();
      }
    }
    return 0;
  },
  async uninstall(p, l) {
    const { uninstall } = await import("./runtime/install.js");
    const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    assertNotRealHome(l.home);
    const browser = opt(p, "--browser");
    if (browser !== undefined && [...p.flags.keys()].some((k) => k !== "--browser")) {
      err(`launchsafe-firewall uninstall: --browser takes no other options. Run "launchsafe-firewall uninstall --help".`);
      return EXIT_USAGE;
    }
    if (!(await humanAtKeyboard())) return 1;
    // CLI audit: --purge deletes whatever the data directory resolves to; it must plainly be the firewall's, checked
    // before anything is changed.
    if (flag(p, "--purge")) {
      const { purgeRefusal } = await import("./runtime/purge.js");
      const why = purgeRefusal(l);
      if (why !== null) {
        err(`launchsafe-firewall uninstall: --purge refused: ${why}. Nothing was changed.`);
        return 1;
      }
    }
    if (approverPublicKey(l) !== null) unlockApprover(l, await readSecret("Approval passphrase: "));
    else if (flag(p, "--purge")) {
      // An overridden data directory without a key does not skip the passphrase: the default one's key decides.
      const { trustedHome } = await import("./runtime/home-trust.js");
      const def = layout(join(trustedHome(process.env).home, ".launchsafe-firewall"));
      if (resolve(def.home) !== resolve(l.home) && approverPublicKey(def) !== null) unlockApprover(def, await readSecret("Approval passphrase: "));
    }
    if (browser !== undefined) {
      const { uninstallHost } = await import("./runtime/native/browsers.js");
      const res = uninstallHost(l, browser === "all" ? undefined : (browser as import("./runtime/native/browsers.js").Browser));
      for (const r of res) out(r.action === "removed" ? `Removed the browser link's host manifest ${r.manifest}` : r.action === "left-edited" ? `Left ${r.manifest} in place: it changed since the firewall wrote it.` : `${r.manifest} was already gone.`);
      if (res.length === 0) out(`The browser link was not installed for ${browser === "all" ? "any browser" : browser}.`);
      return 0;
    }
    const scope = opt(p, "--scope") as "user" | "project" | "local" | undefined;
    const agent = opt(p, "--agent") as "claude" | "codex" | "gemini" | "cursor" | undefined;
    const { adapterFor } = await import("./adapters/index.js");
    if (flag(p, "--force") && !flag(p, "--restore-backup")) {
      err(`launchsafe-firewall uninstall: --force only applies with --restore-backup. Run "launchsafe-firewall uninstall --help".`);
      return EXIT_USAGE;
    }
    let force = flag(p, "--force");
    if (flag(p, "--restore-backup") && !force) {
      const { restoreEdits } = await import("./runtime/install.js");
      const edits = restoreEdits(l, { ...(agent !== undefined ? { agent, settings: adapterFor(agent).settings } : {}), ...(scope !== undefined ? { scope, projectDir: resolve(opt(p, "--project") ?? process.cwd()) } : {}) });
      if (edits.length > 0) {
        for (const e of edits) out(`${e.path} has ${e.differences} difference${e.differences === 1 ? "" : "s"} from what the firewall installed (settings you changed since): restoring the backup discards them.`);
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        try {
          force = /^y(es)?$/i.test((await rl.question("Restore the backup anyway? The current file is saved beside it first. (yes/no) ")).trim());
        } finally {
          rl.close();
        }
        if (!force) {
          out("Nothing was restored. Run it again and answer yes, or use --force, or plain uninstall (which keeps your edits).");
          return 1;
        }
      }
    }
    const res = uninstall(l, { restoreBackup: flag(p, "--restore-backup"), force, specFor: (id) => adapterFor(id).settings, ...(agent !== undefined ? { agent, settings: adapterFor(agent).settings } : {}), ...(scope !== undefined ? { scope, projectDir: resolve(opt(p, "--project") ?? process.cwd()) } : {}) });
    for (const r of res) {
      if (r.restored === "kept-edits") {
        out(`Left ${r.path} as it is: it has ${r.differences ?? 0} change${r.differences === 1 ? "" : "s"} since install (use --force to restore the backup over them).`);
        continue;
      }
      out(`${r.restored === "restored-backup" ? (r.removedFile === true ? "Restored the backup of (the file did not exist before install, so it was removed)" : "Restored the backup of") : r.restored === "removed-hooks" ? "Removed the firewall's hooks from" : "Nothing to do for"} ${r.path}`);
      if (r.savedCopy !== undefined) out(`The file as it was just before the restore is saved as ${r.savedCopy}${r.differences !== undefined && r.differences > 0 ? ` (it holds the ${r.differences} change${r.differences === 1 ? "" : "s"} the restore discarded)` : ""}.`);
      if (r.linkedTo !== undefined) out(`${r.path} is a symbolic link to ${r.linkedTo}: the change was written to that file and the link was kept.`);
    }
    // The sandbox profile stays unless asked (a person may want to keep the sandbox).
    if (flag(p, "--remove-sandbox") || flag(p, "--restore-backup")) {
      const { removeSandboxProfiles } = await import("./runtime/sandbox.js");
      const restored = res.filter((r) => r.restored === "restored-backup").map((r) => r.path);
      for (const s of removeSandboxProfiles(l, { skipPaths: restored })) out(s.action === "left" ? `The sandbox profile in ${s.path} went with the restored backup (or the file is gone).` : `${s.action === "restored" ? "Put back your earlier sandbox settings in" : "Removed the sandbox profile from"} ${s.path}`);
    }
    // Gemini CLI's seatbelt profile goes with the last of its hooks.
    const { readRecords } = await import("./runtime/install.js");
    if ((agent === undefined || agent === "gemini") && !readRecords(l).some((r) => r.agent === "gemini")) {
      const { removeSeatbelt } = await import("./runtime/gemini-seatbelt.js");
      const sb = removeSeatbelt(l);
      if (sb !== null) out(sb.action === "removed" ? `Removed Gemini CLI's seatbelt profile ${sb.path}.` : sb.action === "left-edited" ? `Left ${sb.path} in place: it changed since the firewall wrote it.` : `Gemini CLI's seatbelt profile ${sb.path} was already gone.`);
    }
    if (res.length === 0) out("The firewall's hooks were not installed in any settings file it recorded.");
    if (flag(p, "--purge")) {
      // The firewall's hooks still run from a settings file you changed since install: its state stays with them.
      const kept = res.filter((r) => r.restored === "kept-edits");
      if (kept.length > 0) {
        err(`launchsafe-firewall uninstall: ${l.home} was not deleted, because the firewall's hooks are still in ${kept.map((r) => r.path).join(", ")}. Remove them first (--force with --restore-backup, or by hand), then run --purge again.`);
        return 1;
      }
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      let typed = "";
      try {
        typed = (await rl.question(`This deletes ${l.home} (state, queue, decision log and signing key). Type the path to confirm: `)).trim();
      } finally {
        rl.close();
      }
      if (resolve(typed) !== resolve(l.home)) {
        out(`Nothing was deleted: the path typed was not ${l.home}.`);
        return 1;
      }
      rmSync(l.home, { recursive: true, force: true });
      out(`Deleted ${l.home} (state, queue, decision log and signing key).`);
    }
    return 0;
  },
  async doctor(p, l) {
    const { doctor } = await import("./runtime/doctor.js");
    const project = resolve(opt(p, "--project") ?? process.cwd());
    if (flag(p, "--repair-state")) {
      if (flag(p, "--fix") || flag(p, "--dry-run") || flag(p, "--ci") || opt(p, "--scope") !== undefined) {
        err(`launchsafe-firewall doctor: --repair-state stands alone. Run "launchsafe-firewall doctor --help".`);
        return EXIT_USAGE;
      }
      return repairInstallState(l, project);
    }
    if (flag(p, "--ci")) {
      if (flag(p, "--fix") || flag(p, "--dry-run") || opt(p, "--scope") !== undefined) {
        err(`launchsafe-firewall doctor: --ci only checks; it does not take --fix, --scope or --dry-run. Run "launchsafe-firewall doctor --help".`);
        return EXIT_USAGE;
      }
      const { doctorCi } = await import("./runtime/doctor.js");
      const checks = doctorCi(l, project);
      const failed = checks.filter((c) => c.status === "fail");
      if (flag(p, "--json")) out(JSON.stringify({ ok: failed.length === 0, checks }, null, 2));
      else {
        for (const c of checks) out(`${c.status === "ok" ? "ok  " : c.status === "warn" ? "WARN" : "FAIL"}  ${c.name}: ${c.detail}`);
        out(failed.length === 0 ? "\nNo check failed: the firewall's hooks are installed with the exit-2 wrapper, watch mode is off, and no agent settings file these checks read switches the hooks off or reaches into them." : `\n${failed.length} check${failed.length === 1 ? "" : "s"} failed: the firewall is not installed or enforcing here, or an agent's hooks, the firewall's included, can be switched off or bypassed.`);
      }
      return failed.length > 0 ? 1 : 0;
    }
    if (!flag(p, "--fix") && (flag(p, "--dry-run") || opt(p, "--scope") !== undefined)) {
      err(`launchsafe-firewall doctor: --scope and --dry-run only apply with --fix. Run "launchsafe-firewall doctor --help".`);
      return EXIT_USAGE;
    }
    const { scoreLines } = await import("./runtime/score.js");
    const checks = doctor(l, project);
    if (flag(p, "--json")) out(JSON.stringify(checks, null, 2));
    else {
      for (const c of checks.filter((x) => x.name !== "protection score")) out(`${c.status === "ok" ? "ok  " : c.status === "warn" ? "WARN" : "FAIL"}  ${c.name}: ${c.detail}`);
      out(`\n${scoreLines(checks).join("\n")}`);
    }
    if (flag(p, "--fix")) return doctorFix(l, project, checks, { scope: (opt(p, "--scope") ?? "user") as "user" | "project" | "local", dryRun: flag(p, "--dry-run") });
    return checks.some((c) => c.status === "fail") ? 1 : 0;
  },
  async update(p, l) {
    const { intelDir, runUpdate } = await import("./runtime/intel.js");
    const { parseEcosystem } = await import("./engine/packages.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    assertNotRealHome(intelDir(l.home));
    const list = opt(p, "--ecosystem");
    const ecosystems = list === undefined ? undefined : list.split(",").map((x) => parseEcosystem(x));
    if (ecosystems !== undefined && ecosystems.some((e) => e === null)) {
      err(`launchsafe-firewall update: --ecosystem must list npm, PyPI, crates.io, RubyGems, Go, Maven, NuGet or Packagist. Run "launchsafe-firewall update --help".`);
      return EXIT_USAGE;
    }
    // The malicious-package lists decide what installs are denied: never fetched over plain HTTP, which anyone on
    // the path could rewrite (loopback only, for a local mirror or the tests' server).
    const src = opt(p, "--source");
    if (src !== undefined && /^http:\/\//i.test(src)) {
      let host = "";
      try {
        host = new URL(src).hostname;
      } catch {
        host = "";
      }
      if (!["127.0.0.1", "localhost", "[::1]", "::1"].includes(host)) {
        err("launchsafe-firewall update: --source must be https:// (or a local directory); plain http:// can be rewritten on the way.");
        return EXIT_USAGE;
      }
    }
    if (!(await humanAtKeyboard())) return 1;
    return runUpdateCommand(l, { ...(opt(p, "--source") !== undefined ? { source: opt(p, "--source") as string } : {}), ...(ecosystems !== undefined ? { ecosystems: ecosystems as NonNullable<(typeof ecosystems)[number]>[] } : {}) }, runUpdate);
  },
  async status(p, l) {
    const { readRecords } = await import("./runtime/install.js");
    const { listQueue, recentSessions } = await import("./runtime/store.js");
    const { tailLog } = await import("./runtime/log.js");
    const { formatStatus, terminalWidth } = await import("./runtime/report.js");
    const { loadPolicy } = await import("./runtime/config.js");
    const { inUnattendedHours } = await import("./policy.js");
    const { lastNotificationAt } = await import("./runtime/notify.js");
    const recs = readRecords(l);
    const pending = listQueue(l).items.filter((i) => i.status === "pending");
    const tail = tailLog(l, 200);
    const recent = tail.filter((e) => e.event.type === "decision");
    const proposedSessions = tail.filter((e) => e.event.type === "spawned_prompt").map((e) => ({ session: String(e.event.session ?? ""), preview: String(e.event.preview ?? "") }));
    const by = (v: string): number => recent.filter((e) => e.event.verdict === v).length;
    const cfg = loadPolicy(l, [process.cwd()]).config;
    const hours = cfg.unattendedHours.map((h) => `${h.from}-${h.to}`).join(", ");
    const unattended = cfg.unattended
      ? { on: true, why: "the policy sets it" }
      : process.env.LAUNCHSAFE_FIREWALL_UNATTENDED === "1"
        ? { on: true, why: "LAUNCHSAFE_FIREWALL_UNATTENDED=1" }
        : inUnattendedHours(cfg.unattendedHours, new Date())
          ? { on: true, why: `inside unattended hours ${hours}` }
          : { on: false, why: `${hours !== "" ? `unattended hours ${hours}; ` : ""}sessions run with claude -p or in dontAsk mode are always unattended` };
    const data = {
      version: VERSION,
      stateDir: l.home,
      installedIn: recs.map((r) => `${r.scope} (${r.path})`),
      sessions: recentSessions(l),
      held: pending.length,
      unattended,
      lastNotification: lastNotificationAt(l),
      decisions: { allow: by("allow"), ask: by("ask"), queue: by("queue"), deny: by("deny"), total: recent.length },
      ...(proposedSessions.length > 0 ? { proposedSessions } : {}),
    };
    // Stale malicious-package data is still used, but the person should know.
    const { snapshotAgeDays } = await import("./runtime/intel.js");
    const { packageIntelPolicy } = await import("./engine/packages.js");
    const age = snapshotAgeDays(l.home);
    const stale = age !== null && age > packageIntelPolicy(cfg).maxSnapshotAgeDays ? `malicious-package data is ${age} days old: run "launchsafe-firewall update"` : null;
    // In log mode, the friction enforcing the task scope would add (it shows what enforcing would cost).
    const { scopeCounts } = await import("./runtime/scope.js");
    const sc = scopeCounts(l);
    const taskScope = { mode: cfg.taskScope.mode, ...sc };
    const scopeLine = cfg.taskScope.mode === "off" ? null : cfg.taskScope.mode === "log" ? `Task scope (log only): ${sc.wouldAsk} action${sc.wouldAsk === 1 ? "" : "s"} would have been asked by task scope` : `Task scope (enforced): ${sc.asked} action${sc.asked === 1 ? "" : "s"} asked or held by task scope`;
    // Messages withheld from the agent, waiting for the person.
    const { heldCount } = await import("./runtime/quarantine.js");
    const mailHeld = heldCount(l, "email");
    const mailLine = mailHeld === 0 ? null : `Mail withheld from the agent: ${mailHeld} ${mailHeld === 1 ? "message" : "messages"} (launchsafe-firewall mail quarantine)`;
    // Phone approvals, only once a phone is paired.
    const { relayStatusLine, readRelayState } = await import("./runtime/relay/files.js");
    const { deviceIdOf } = await import("./runtime/relay/keys.js");
    const phoneLine = relayStatusLine(l, deviceIdOf(l) !== null);
    // Watch mode: say so plainly, every time (risky actions run while it is on).
    const { pinnedWatchKey, watchState } = await import("./runtime/rollout.js");
    const { homedir } = await import("node:os");
    const ws = watchState(l, loadPolicy(l, [process.cwd()]), pinnedWatchKey(l, homedir()));
    const rolloutLine = ws.active ? `Rollout mode: WATCH. Risky actions are logged and allowed, except the always-enforced core (launchsafe-firewall rollout report; rollout enforce to switch back)` : ws.requested === "watch" ? `Rollout mode: enforce (watch requested but not in effect: ${ws.problem ?? ""})` : null;
    if (flag(p, "--json")) out(JSON.stringify({ ...data, packageDataAgeDays: age, taskScope, mailWithheld: mailHeld, rollout: { mode: ws.active ? "watch" : "enforce", requested: ws.requested, layer: ws.layer }, ...(phoneLine !== null ? { phone: readRelayState(l) } : {}) }, null, 2));
    else {
      out(formatStatus(data, { width: terminalWidth(process.stdout.columns) }));
      if (rolloutLine !== null) out(rolloutLine);
      if (stale !== null) out(stale);
      if (scopeLine !== null) out(scopeLine);
      if (mailLine !== null) out(mailLine);
      if (phoneLine !== null) out(phoneLine);
    }
    return 0;
  },
  queue: queueList,
  "queue list": queueList,
  async "queue show"(p, l) {
    const { getQueueItem } = await import("./runtime/store.js");
    const id = p.positionals[0] ?? "";
    const it = getQueueItem(l, id);
    if (it === null) {
      err(`No queue item "${id}". Run: launchsafe-firewall queue list`);
      return 1;
    }
    if (flag(p, "--json")) {
      out(JSON.stringify(it, null, 2));
      return 0;
    }
    const { formatShow, terminalWidth } = await import("./runtime/report.js");
    const { readText } = await import("./runtime/fsutil.js");
    let current: string | null = null;
    try {
      current = it.proposal !== undefined && it.proposal.target.startsWith("/") ? readText(it.proposal.target) : null;
    } catch {
      current = null;
    }
    out(formatShow(it, { width: terminalWidth(process.stdout.columns), currentContent: current }));
    // I3: say what was cut when the action was held (it cannot be shown: it was never stored).
    const { itemTruncation } = await import("./runtime/store.js");
    const cut = itemTruncation(it);
    if (cut.length > 0) out(`Not shown in full (cut when it was held): ${cut.join("; ")}. Approving it needs --i-saw-truncated.`);
    return 0;
  },
  "queue review": (p, l) => queueDecide(p, l, "review"),
  friction: learnedCommand("friction"),
  "friction report": learnedCommand("friction report"),
  allow: learnedCommand("allow"),
  "allow list": learnedCommand("allow list"),
  "allow add": learnedCommand("allow add"),
  "allow never": learnedCommand("allow never"),
  "allow remove": learnedCommand("allow remove"),
  "queue approve": (p, l) => queueDecide(p, l, "approve"),
  "queue reject": (p, l) => queueDecide(p, l, "reject"),
  pins: pinsList,
  "pins list": pinsList,
  async "pins accept"(p, l) {
    const { acceptPins, loadPins, pendingFor } = await import("./runtime/pins.js");
    const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
    const { appendLog } = await import("./runtime/log.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    assertNotRealHome(l.home);
    if (!(await humanAtKeyboard())) return 1;
    let pending: ReturnType<typeof pendingFor> = [];
    try {
      const all = loadPins(l).pins.pending;
      pending = p.positionals.flatMap((a) => pendingFor(all, a));
    } catch (e) {
      err((e as Error).message);
      return 1;
    }
    if (pending.length === 0) {
      out(`No pending MCP pin change for: ${p.positionals.join(" ")}. Run: launchsafe-firewall pins`);
      return 1;
    }
    for (const c of pending) out(`  ${c.name}: ${c.detail}`);
    if (approverPublicKey(l) !== null) unlockApprover(l, await readSecret("Approval passphrase: "));
    for (const a of acceptPins(l, p.positionals)) {
      if (a.changes.length === 0) continue;
      appendLog(l, { type: "mcp_pin", change: "accepted", server: a.server, kinds: a.changes.map((c) => c.kind) });
      out(`Re-pinned ${a.server} (${a.changes.length} change${a.changes.length === 1 ? "" : "s"}). New sessions no longer treat it as changed.`);
    }
    return 0;
  },
  approver: approverStatus,
  "approver status": approverStatus,
  async "approver init"(_p, l) {
    const { initApprover, approverPath } = await import("./runtime/approver.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    assertNotRealHome(approverPath(l));
    if (!(await humanAtKeyboard())) return 1;
    initApprover(l, await newPassphrase());
    out(await repinMessage(l, "Set."));
    return 0;
  },
  async "approver rotate"(_p, l) {
    const { rotateApprover, approverPath, approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    assertNotRealHome(approverPath(l));
    if (!(await humanAtKeyboard())) return 1;
    const old = await readSecret("Current approval passphrase: ");
    const oldKey = approverPublicKey(l);
    const fresh = await newPassphrase();
    rotateApprover(l, old, fresh);
    out(await repinMessage(l, "Changed. Approvals signed with the old key no longer count."));
    // The vault index is signed with the approval key and the file store is keyed by the passphrase.
    const { afterApproverRotate } = await import("./vault-cli.js");
    for (const line of await afterApproverRotate(l, oldKey, unlockApprover(l, fresh), old, fresh)) out(line);
    return 0;
  },
  log: logTail,
  "log tail": logTail,
  async "log verify"(p, l) {
    const bundle = p.positionals[0];
    if (bundle !== undefined) return verifyBundleCommand(p, bundle);
    if (p.lists !== undefined || flag(p, "--json") || flag(p, "--no-pin")) {
      err('launchsafe-firewall log verify: --key, --anchor, --no-pin and --json are for a bundle: log verify <bundle> [--key ...] [--anchor ...]. Run "launchsafe-firewall log verify --help".');
      return EXIT_USAGE;
    }
    const { verifyLog } = await import("./runtime/log.js");
    const v = verifyLog(l);
    out(v.ok ? `OK: ${v.entries} entries in ${v.files} file(s); chain, hashes and signatures are valid. This checks the log against its own key; for tamper-evidence use log anchor and log verify <bundle> --key.` : `PROBLEMS:\n${v.problems.join("\n")}`);
    return v.ok ? 0 : 1;
  },
  async "log export"(p, l) {
    // Person-run (docs/logs.md). The real gate is the hook: an agent's tool call running it is FW-TAMPER.
    // Here, as for log anchor, a person at the keyboard: a terminal on standard input (standard output may be
    // a pipe, for --out -), and not a descendant of a Claude Code session.
    if (!(await personAtTerminal("log export"))) return 1;
    const { exportLog, ExportRefused } = await import("./logbundle/export.js");
    const target = opt(p, "--out");
    if (target === undefined) {
      err('launchsafe-firewall log export: needs --out FILE (or --out - for standard output). Run "launchsafe-firewall log export --help".');
      return EXIT_USAGE;
    }
    let r: Awaited<ReturnType<typeof exportLog>>;
    try {
      r = exportLog(l, { ...(opt(p, "--from") !== undefined ? { from: opt(p, "--from") as string } : {}), ...(opt(p, "--to") !== undefined ? { to: opt(p, "--to") as string } : {}) });
    } catch (e) {
      if (!(e instanceof ExportRefused)) throw e;
      err(`Not exported: ${e.message}`);
      return 1;
    }
    const m = r.manifest;
    const summary = `${m.entries} entries, sequence ${m.firstSeq} to ${m.lastSeq}${m.fromStart && m.toEnd ? " (the whole log)" : ""}. Signed by ${r.fingerprint}: keep that fingerprint somewhere else and check with "launchsafe-firewall log verify <bundle> --key ${r.fingerprint}".`;
    // I6: what was taken off the machine is noted beside the log (not in it: an entry after the export would put
    // the bundle's end before the log's), so pruning can tell exported files from never-exported ones.
    const noteExport = async (): Promise<void> => {
      const { noteLogExported } = await import("./runtime/log.js");
      noteLogExported(l, m.lastSeq);
    };
    if (target === "-") {
      // The bundle itself goes out byte for byte (no safeText: it is JSON whose hashes must not change).
      write(1, r.text);
      err(`Exported ${summary}`);
      await noteExport();
      return 0;
    }
    const { writeNew } = await import("./runtime/fsutil.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    const { insideFirewallHome } = await import("./logbundle/place.js");
    const path = resolve(target);
    if (insideFirewallHome(l, path)) {
      err(`Not exported: ${path} is inside the firewall's directory (${l.home}); write the bundle somewhere else.`);
      return 1;
    }
    assertNotRealHome(path);
    try {
      // O_EXCL: never replaces a file, never writes through a symbolic link.
      writeNew(path, r.text);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      err(code === "EEXIST" ? `Not exported: ${path} already exists (an export never replaces a file).` : `Not exported: could not write ${path} (${code ?? (e as Error).message}).`);
      return 1;
    }
    // Success only for a file that reads back as the bundle that verified.
    if (readFileSync(path, "utf8") !== r.text) {
      err(`Not exported: ${path} did not read back as written; it is incomplete and should be deleted.`);
      return 1;
    }
    out(`Exported ${summary}\nWrote ${path}.`);
    await noteExport();
    return 0;
  },
  async "log anchor"(p, l) {
    // Person-run only: the hooks refuse it to an agent (FW-TAMPER), and it needs a person at the keyboard.
    if (!(await humanAtKeyboard())) return 1;
    const file = opt(p, "--file");
    const repo = opt(p, "--git-notes");
    const exec = flag(p, "--exec");
    const chosen = [file !== undefined, repo !== undefined, exec].filter(Boolean).length;
    if (chosen !== 1 || (!exec && p.positionals.length > 0) || (exec && p.positionals.length === 0)) {
      err('launchsafe-firewall log anchor: choose one place: --file PATH, --git-notes REPO, or --exec -- <command> [args...]. Run "launchsafe-firewall log anchor --help".');
      return EXIT_USAGE;
    }
    const { makeAnchorRecord, writeAnchor, assertAnchorPlace, AnchorRefused } = await import("./logbundle/anchor.js");
    const { appendLog } = await import("./runtime/log.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    try {
      const target = file !== undefined ? ({ kind: "file", path: resolve(file) } as const) : repo !== undefined ? ({ kind: "git", repo: resolve(repo) } as const) : ({ kind: "exec", argv: p.positionals } as const);
      assertAnchorPlace(l, target);
      if (target.kind === "file") assertNotRealHome(target.path);
      const record = makeAnchorRecord(l);
      const where = writeAnchor(record, target);
      // The anchoring itself is logged (where it went is not: a command's arguments can name a bucket or a token).
      appendLog(l, { type: "log_anchor", seq: record.seq, hash: record.hash, to: file !== undefined ? "file" : repo !== undefined ? "git" : "exec" });
      out(`Anchored sequence ${record.seq} (${record.hash}), key ${record.key}: ${where}.`);
      return 0;
    } catch (e) {
      if (!(e instanceof AnchorRefused)) throw e;
      err(`Not anchored: ${e.message}`);
      return 1;
    }
  },
  async "log rotate"(_p, l) {
    // R20: it changes the tripwires, the policy or the log: a person at the keyboard, like update and pins accept.
    if (!(await humanAtKeyboard())) return 1;
    const { rotateNow } = await import("./runtime/log.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    assertNotRealHome(l.log);
    // A rotation can prune the oldest files past the limit (their entries are gone): like approving, it needs the
    // approval passphrase when one is set.
    const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
    if (approverPublicKey(l) !== null) unlockApprover(l, await readSecret("Approval passphrase: "));
    rotateNow(l);
    out("Rotated. The next entry records any file this pruned (log_pruned).");
    return 0;
  },
  policy: policyShow,
  "policy show": policyShow,
  async "policy validate"(_p, l) {
    const { loadPolicy } = await import("./runtime/config.js");
    const pol = loadPolicy(l, [process.cwd()]);
    out(pol.error === undefined ? `Valid: ${pol.sources.join(", ")}` : `Invalid: ${pol.error}`);
    for (const n of pol.notes) out(n);
    for (const i of pol.ignored) out(`Ignored: ${i}`);
    return pol.error === undefined ? 0 : 1;
  },
  async "policy init"(_p, l) {
    // R20: it changes the tripwires, the policy or the log: a person at the keyboard, like update and pins accept.
    if (!(await humanAtKeyboard())) return 1;
    const { atomicWrite, readText } = await import("./runtime/fsutil.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    const { POLICY_VERSION } = await import("./policy.js");
    assertNotRealHome(l.policy);
    if (readText(l.policy) !== null) {
      err(`${l.policy} already exists.`);
      return 1;
    }
    atomicWrite(l.policy, `${JSON.stringify({ version: POLICY_VERSION }, null, 2)}\n`);
    out(`Wrote ${l.policy}. A list you set replaces the built-in list for that key; see docs/policy.md and "launchsafe-firewall policy show".`);
    return 0;
  },
  async "policy migrate"(_p, l) {
    // R20: it changes the tripwires, the policy or the log: a person at the keyboard, like update and pins accept.
    if (!(await humanAtKeyboard())) return 1;
    const { atomicWrite, readTextExact, writeNew } = await import("./runtime/fsutil.js");
    const { assertNotRealHome } = await import("./runtime/guard.js");
    const { planMigration, PolicyError, POLICY_VERSION } = await import("./policy.js");
    assertNotRealHome(l.policy);
    // The policy loader refuses a file that starts with a byte order mark; migrate reads it the same way, and its backup is the original bytes.
    const text = readTextExact(l.policy);
    if (text === null) {
      out(`${l.policy} does not exist; nothing to migrate.`);
      return 0;
    }
    let plan: ReturnType<typeof planMigration>;
    try {
      plan = planMigration(JSON.parse(text) as unknown, l.policy);
    } catch (e) {
      // Nothing is written for a file this firewall cannot read (invalid, or a newer schema).
      err(`Not migrated: ${e instanceof PolicyError ? e.message : `${l.policy}: not valid JSON: ${(e as Error).message}`}`);
      return 1;
    }
    if (plan === null) {
      out(`${l.policy} is already version ${POLICY_VERSION}.`);
      return 0;
    }
    // The original bytes first, under a name no earlier backup holds, then the atomic rewrite.
    let backup = `${l.policy}.v${plan.from}.bak`;
    for (let n = 2; ; n++) {
      assertNotRealHome(backup);
      try {
        writeNew(backup, text);
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST" || n > 100) throw e;
        backup = `${l.policy}.v${plan.from}.${n}.bak`;
      }
    }
    atomicWrite(l.policy, `${JSON.stringify(plan.doc, null, 2)}\n`);
    out(`Rewrote ${l.policy} as policy version ${POLICY_VERSION} (from version ${plan.from}; same settings). The original is in ${backup}.`);
    return 0;
  },
  rollout: rolloutStatus,
  "rollout status": rolloutStatus,
  async "rollout watch"(p, l) {
    const { assertNotRealHome } = await import("./runtime/guard.js");
    assertNotRealHome(l.policy);
    if (!(await humanAtKeyboard())) return 1;
    const { loadPolicy } = await import("./runtime/config.js");
    const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
    const { DEFAULT_DAYS, enforcedCoreLines, pinnedWatchKey, recordRolloutChange, removeGrant, setUserRolloutMode, watchState, writeGrant } = await import("./runtime/rollout.js");
    const { homedir } = await import("node:os");
    const pol = loadPolicy(l, [process.cwd()]);
    if (pol.rollout.layer === "managed") {
      if (pol.rollout.mode === "enforce") {
        err(`The managed policy (${pol.rollout.path ?? "managed"}) sets rollout.mode "enforce", so watch mode cannot be turned on here. Ask your administrator.`);
        return 1;
      }
      out(`Watch mode is already on: the managed policy (${pol.rollout.path ?? "managed"}) sets it.`);
      return 0;
    }
    if (approverPublicKey(l) === null) {
      err('Watch mode needs the approval passphrase, which is not set. In your own terminal run "launchsafe-firewall approver init", then "launchsafe-firewall install" again, then this command.');
      return 1;
    }
    const days = opt(p, "--days") !== undefined ? Number(opt(p, "--days")) : DEFAULT_DAYS;
    out(`Watch mode lets risky actions run for ${days} day${days === 1 ? "" : "s"}: the firewall logs what it would have asked about, held or blocked. These rules still ask or block:`);
    for (const line of enforcedCoreLines()) out(`  ${line}`);
    const priv = unlockApprover(l, await readSecret("Approval passphrase: "));
    const g = writeGrant(l, priv, { days });
    // A change the signed log could not record is not made: the grant goes again and nothing else changes.
    try {
      recordRolloutChange(l, { mode: "watch", by: "person", grant: g.id, until: g.until, policy: l.policy });
    } catch (e) {
      removeGrant(l);
      throw e;
    }
    let res: ReturnType<typeof setUserRolloutMode>;
    try {
      res = setUserRolloutMode(l, "watch");
    } catch (e) {
      // The policy line could not be written: end the grant again, with a signed record of that.
      removeGrant(l);
      try {
        recordRolloutChange(l, { mode: "enforce", by: "person", revoked: [g.id], why: "the policy file could not be written" });
      } catch {
        // The grant is gone, so watch mode is off whatever the log says.
      }
      throw e;
    }
    const st = watchState(l, loadPolicy(l, [process.cwd()]), pinnedWatchKey(l, homedir()));
    if (!st.active) {
      err(`The grant (${g.id}) is recorded, but watch mode is NOT in effect: ${st.problem ?? "unknown reason"}.`);
      return 1;
    }
    out(`Watch mode is on until ${g.until} (grant ${g.id}).${res.backup !== null ? ` Your policy file was saved first as ${res.backup}.` : ""}`);
    out('See what enforcing would have done: launchsafe-firewall rollout report. Switch back: launchsafe-firewall rollout enforce.');
    return 0;
  },
  async "rollout enforce"(_p, l) {
    const { assertNotRealHome } = await import("./runtime/guard.js");
    assertNotRealHome(l.policy);
    if (!(await humanAtKeyboard())) return 1;
    const { loadPolicy } = await import("./runtime/config.js");
    const { readGrant, recordRolloutChange, removeGrant, setUserRolloutMode } = await import("./runtime/rollout.js");
    // The signed revocation first (the grant id is kept as revoked), then the grant goes.
    const g = readGrant(l);
    recordRolloutChange(l, { mode: "enforce", by: "person", ...(typeof g === "object" && g !== null ? { revoked: [g.id] } : {}), policy: l.policy });
    removeGrant(l);
    let note = "";
    try {
      const res = setUserRolloutMode(l, "enforce");
      if (res.backup !== null) note = ` Your policy file was saved first as ${res.backup}.`;
    } catch (e) {
      note = ` The policy file was left as it is (${(e as Error).message}); without the grant it cannot turn watch mode on.`;
    }
    const pol = loadPolicy(l, [process.cwd()]);
    if (pol.rollout.layer === "managed" && pol.rollout.mode === "watch") {
      out(`Your watch-mode grant is revoked, but the managed policy (${pol.rollout.path ?? "managed"}) keeps watch mode on. Ask your administrator.${note}`);
      return 1;
    }
    out(`Enforcing: every verdict applies again.${note}`);
    return 0;
  },
  async "rollout report"(p, l) {
    const { loadPolicy } = await import("./runtime/config.js");
    const { formatWatchReport, watchReport, watchState } = await import("./runtime/rollout.js");
    const raw = opt(p, "--since");
    let since: Date | undefined;
    if (raw !== undefined) {
      const days = /^(\d{1,4})d$/.exec(raw);
      since = days !== null ? new Date(Date.now() - Number(days[1]) * 86_400_000) : new Date(raw);
      if (Number.isNaN(since.getTime())) {
        err('launchsafe-firewall rollout report: --since must be a date (2026-10-01) or a number of days (7d). Run "launchsafe-firewall rollout report --help".');
        return EXIT_USAGE;
      }
    }
    const { pinnedWatchKey } = await import("./runtime/rollout.js");
    const { homedir } = await import("node:os");
    const state = watchState(l, loadPolicy(l, [process.cwd()]), pinnedWatchKey(l, homedir()));
    const ex = opt(p, "--examples");
    const report = watchReport(l, { ...(since !== undefined ? { since } : {}), ...(ex !== undefined ? { examples: Number(ex) } : {}) });
    if (flag(p, "--json")) out(JSON.stringify({ mode: state.active ? "watch" : "enforce", state: { requested: state.requested, active: state.active, layer: state.layer, ...(state.problem !== undefined ? { problem: state.problem } : {}) }, ...report }, null, 2));
    else out(formatWatchReport(report, state));
    return 0;
  },
  canary: canaryList,
  "canary list": canaryList,
  async "canary plant"(p, l) {
    const { plantCanaries, CANARY_KINDS } = await import("./runtime/canaries.js");
    const raw = opt(p, "--kinds");
    const kinds = raw === undefined ? undefined : raw.split(",").map((k) => k.trim());
    const bad = kinds?.find((k) => !(CANARY_KINDS as readonly string[]).includes(k));
    if (kinds !== undefined && bad !== undefined) {
      err(`launchsafe-firewall canary plant: unknown kind "${bad}" (expected ${CANARY_KINDS.join(", ")}). Run "launchsafe-firewall canary plant --help".`);
      return EXIT_USAGE;
    }
    // R20: it changes the tripwires, the policy or the log: a person at the keyboard, like update and pins accept.
    if (!(await humanAtKeyboard())) return 1;
    try {
      const r = plantCanaries(l, { ...(opt(p, "--workspace") !== undefined ? { workspace: opt(p, "--workspace") as string } : {}), home: flag(p, "--home"), ...(kinds !== undefined ? { kinds: kinds as CanaryKind[] } : {}) });
      for (const c of r.planted) out(`Planted ${c.kind} decoy ${c.id}: ${c.path}`);
      for (const n of r.notes) out(`Note: ${n}`);
      if (r.planted.length > 0) out("Each file is mode 600 and, in a git repository, listed in .git/info/exclude (not .gitignore), so git add -A will not commit it. Remove them with: launchsafe-firewall canary remove --all");
      return 0;
    } catch (e) {
      if (e instanceof Error && e.name === "RealHomeRefused") throw e;
      err(`launchsafe-firewall canary plant: ${(e as Error).message}`);
      return 1;
    }
  },
  async "canary remove"(p, l) {
    const { removeCanaries } = await import("./runtime/canaries.js");
    const id = p.positionals[0];
    if (id === undefined && !flag(p, "--all")) {
      err('launchsafe-firewall canary remove: name a decoy id or pass --all. Run "launchsafe-firewall canary list".');
      return EXIT_USAGE;
    }
    if (id !== undefined && flag(p, "--all")) {
      err('launchsafe-firewall canary remove: give an id or --all, not both. Run "launchsafe-firewall canary remove --help".');
      return EXIT_USAGE;
    }
    // R20: it changes the tripwires, the policy or the log: a person at the keyboard, like update and pins accept.
    if (!(await humanAtKeyboard())) return 1;
    // Removing a decoy takes a tripwire away: it needs the approval passphrase when one is set.
    const { approverPublicKey, unlockApprover } = await import("./runtime/approver.js");
    if (approverPublicKey(l) !== null) unlockApprover(l, await readSecret("Approval passphrase: "));
    try {
      const r = removeCanaries(l, { ...(id !== undefined ? { id } : {}), all: flag(p, "--all") });
      for (const x of r.removed) out(`Removed ${x}`);
      for (const x of r.kept) out(`Left: ${x}`);
      return 0;
    } catch (e) {
      if (e instanceof Error && e.name === "RealHomeRefused") throw e;
      err(`launchsafe-firewall canary remove: ${(e as Error).message}`);
      return 1;
    }
  },
  scope: scopeShow,
  "scope show": scopeShow,
  async "scope widen"(p, l) {
    const { normalizeWiden } = await import("./engine/scope.js");
    const given = (["--path", "--repo", "--host", "--intent"] as const).filter((f) => opt(p, f) !== undefined);
    if (given.length !== 1) {
      err("launchsafe-firewall scope widen: give exactly one of --path, --repo, --host, --intent");
      return EXIT_USAGE;
    }
    const flagName = given[0] as "--path" | "--repo" | "--host" | "--intent";
    const kind = flagName.slice(2) as "path" | "repo" | "host" | "intent";
    const raw = opt(p, flagName) as string;
    // A path is compared with the targets of writes, which are resolved through symlinks.
    const { realpathSync } = await import("node:fs");
    const real = (p: string): string => {
      try {
        return realpathSync(p);
      } catch {
        return p;
      }
    };
    const w = normalizeWiden(kind, kind === "path" ? real(resolve(raw)) : raw);
    if (w === null) {
      err(`launchsafe-firewall scope widen: not a valid ${kind}: ${raw}`);
      return EXIT_USAGE;
    }
    if (!(await humanAtKeyboard())) return 1;
    const { unlockApprover, signStateChange } = await import("./runtime/approver.js");
    const { widenScope } = await import("./runtime/scope.js");
    const { appendLog } = await import("./runtime/log.js");
    const session = p.positionals[0] as string;
    const priv = unlockApprover(l, await readSecret("Approval passphrase: "));
    const id = widenScope(l, session, w, (fields) => signStateChange(priv, "scope-widen", session, fields));
    appendLog(l, { type: "scope_widen", session, kind: w.kind, value: w.value, id });
    out(`Task scope of session ${session} widened to include ${w.kind} ${w.value} (${id}).`);
    return 0;
  },
  caps: capsShow,
  "caps show": capsShow,
  async "caps raise"(p, l) {
    const { CAP_METRICS } = await import("./engine/caps.js");
    const metric = p.positionals[0] as string;
    const raw = p.positionals[1] as string;
    if (!(CAP_METRICS as readonly string[]).includes(metric)) {
      err(`launchsafe-firewall caps raise: not a limit: ${metric} (one of ${CAP_METRICS.join(", ")})`);
      return EXIT_USAGE;
    }
    const amount = Number(raw);
    if (!/^\d+(?:\.\d+)?$/.test(raw) || !Number.isFinite(amount) || amount <= 0 || (metric !== "costUsd" && !Number.isInteger(amount))) {
      err(`launchsafe-firewall caps raise: the amount must be a positive ${metric === "costUsd" ? "number of US dollars" : "whole number"}: ${raw}`);
      return EXIT_USAGE;
    }
    const session = opt(p, "--session");
    if ((session === undefined) === !flag(p, "--today")) {
      err("launchsafe-firewall caps raise: give exactly one of --session <id> and --today");
      return EXIT_USAGE;
    }
    // FW-TAMPER: an agent may never raise its own limits; a person at the keyboard, with the passphrase.
    if (!(await humanAtKeyboard())) return 1;
    const { unlockApprover, signStateChange } = await import("./runtime/approver.js");
    const { raiseCap } = await import("./runtime/caps.js");
    const unknown = await unknownSession(l, session);
    if (unknown !== null) {
      err(unknown);
      return 1;
    }
    const priv = unlockApprover(l, await readSecret("Approval passphrase: "));
    if (!(await keyMatchesPins(l, priv))) return 1;
    const scope = session !== undefined ? "session" : "day";
    const id = raiseCap(l, { scope, metric: metric as import("./engine/caps.js").CapMetric, amount, ...(session !== undefined ? { session } : {}) }, (subject, fields) => signStateChange(priv, "budget-raise", subject, fields));
    out(`Raised the ${metric} limit by ${amount} ${scope === "session" ? `for session ${session}` : "for today (every session, until local midnight)"} (${id}). The agent can go on.`);
    return 0;
  },
  async "caps reset"(p, l) {
    const session = opt(p, "--session");
    if ((session === undefined) === !flag(p, "--today")) {
      err("launchsafe-firewall caps reset: give exactly one of --session <id> and --today");
      return EXIT_USAGE;
    }
    // FW-TAMPER: only a person starts the counters again, with the passphrase.
    if (!(await humanAtKeyboard())) return 1;
    const { unlockApprover } = await import("./runtime/approver.js");
    const { resetCaps } = await import("./runtime/caps.js");
    const unknown = await unknownSession(l, session);
    if (unknown !== null) {
      err(unknown);
      return 1;
    }
    const priv = unlockApprover(l, await readSecret("Approval passphrase: "));
    if (!(await keyMatchesPins(l, priv))) return 1;
    resetCaps(l, { scope: session !== undefined ? "session" : "day", ...(session !== undefined ? { session } : {}) });
    out(`Started the spending-limit counters again ${session !== undefined ? `for session ${session}` : "for today"}. Run launchsafe-firewall caps show to see the counters, and check why they could not be read (launchsafe-firewall doctor).`);
    return 0;
  },
  check: (_p, l) => checkStdin(l),
  async explain(p, l) {
    if (p.positionals.length === 0) return checkStdin(l);
    const { explainId } = await import("./runtime/explain.js");
    const r = explainId(l, p.positionals[0] as string, { json: flag(p, "--json"), width: process.stdout.columns });
    if (r === null) {
      err(`launchsafe-firewall explain: no rule, queue item or log entry named ${p.positionals[0] ?? ""}. Run "launchsafe-firewall explain --help".`);
      return EXIT_USAGE;
    }
    out(r);
    return 0;
  },
  async ui(p, l) {
    // docs/dashboard.md: only a person at the keyboard; the address (with its token) goes to this terminal only.
    if (!(await humanAtKeyboard())) return 1;
    const { startDashboard } = await import("./ui/server.js");
    const { openBrowser } = await import("./ui/browser.js");
    let stop: () => void = () => undefined;
    const stopped = new Promise<void>((r) => (stop = r));
    const d = await startDashboard({
      layout: l,
      project: resolve(opt(p, "--project") ?? process.cwd()),
      onIdle: () => {
        out("Stopped after 30 minutes without a request. Run launchsafe-firewall ui again for a new address.");
        stop();
      },
      // Why a page failed is shown here, in the person's terminal, never in the browser.
      log: (m) => err(m),
    });
    out(`LaunchSafe Firewall dashboard (read-only), for you only:\n\n  ${d.url}\n\nThis address is not saved anywhere; it stops working when this command stops. Anyone who has it can read your queue and log, so do not paste it into an agent.\nApprovals stay in your terminal: the dashboard shows the exact command to run.`);
    if (!flag(p, "--no-open")) {
      const why = await openBrowser(d.launchUrl);
      out(why === null ? "Opened in your browser." : `Could not open the browser (${why}); open the address above yourself.`);
    }
    out("Press Ctrl-C to stop. It also stops when this terminal closes, and after 30 minutes without a request.");
    const onSignal = (): void => {
      void d.close().then(stop);
    };
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
    // Tied to the terminal that started it (DB5): a closed terminal sends SIGHUP, and a shell killed outright
    // (SIGKILL, no hangup) leaves this process with a new parent, which the poll notices within two seconds.
    process.once("SIGHUP", onSignal);
    const parent = process.ppid;
    const watch = setInterval(() => {
      if (process.ppid !== parent) onSignal();
    }, 2000);
    watch.unref();
    await stopped;
    clearInterval(watch);
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    process.removeListener("SIGHUP", onSignal);
    return 0;
  },
  async run(p, l) {
    const envRaw = p.lists?.get("--env") ?? [];
    const ticket = opt(p, "--ticket");
    const baseEnv = runOverrides.env ?? process.env;
    if (ticket !== undefined) return runWithTicket(p, l, ticket, envRaw, baseEnv);
    // docs/run.md: started by a person. The hooks deny it to an agent (FW-TAMPER); here, a Claude Code
    // session's descendants are refused too. No terminal is required: scripts and CI may start it.
    if (keyboardCheck !== null) {
      if (!(await keyboardCheck())) return 1;
    } else {
      const { agentLaunch } = await import("./runtime/approver.js");
      const why = agentLaunch();
      if (why === "unknown") {
        err(`${unreadAncestry("launchsafe-firewall run")} An agent may not choose its own sandbox.`);
        return 1;
      }
      if (why !== null) {
        err("launchsafe-firewall run was started from inside a coding agent's session (Claude Code, Codex, Gemini CLI or Cursor). Start it from your own terminal or script; an agent may not choose its own sandbox.");
        return 1;
      }
      // I7: the other agents the firewall hooks (Codex, Gemini CLI, Cursor), by their shells' variables or
      // a parent process, and a process started by one of the firewall's own hooks.
      const { agentAncestor, agentEnvMarker } = await import("./runtime/run/guards.js");
      const marker = agentEnvMarker(process.env);
      const parent = marker === null ? agentAncestor() : null;
      if (marker !== null || parent !== null) {
        err(`launchsafe-firewall run was started from inside a coding agent (${marker !== null ? `${marker} is set` : `a parent process is ${parent ?? ""}`}). Start it from your own terminal or script; an agent may not choose its own sandbox.`);
        return 1;
      }
    }
    const { runSandboxed, resolveProgram } = await import("./runtime/run/run.js");
    const { homedir } = await import("node:os");
    const list = (name: string): string[] => (opt(p, name) ?? "").split(",").map((x) => x.trim()).filter((x) => x !== "");
    // I7: the program is resolved once, here, to an absolute path: the binding check below and the sandbox
    // start the same file (no second PATH lookup between them).
    const program = p.positionals[0] !== undefined ? resolveProgram(p.positionals[0], baseEnv, process.cwd()) : null;
    const command = program !== null ? [program, ...p.positionals.slice(1)] : p.positionals;
    // Secrets by reference, for a command bound to them (vault allow <name> --process "<argv>").
    let extraEnv: Record<string, string> | undefined;
    if (envRaw.length > 0) {
      const { parseEnvPairs, resolveRunEnv, EXIT_VAULT_DENIED } = await import("./runtime/run/vault-env.js");
      const parsed = parseEnvPairs(envRaw);
      if (!parsed.ok) {
        err(`launchsafe-firewall run: ${parsed.why}`);
        return EXIT_USAGE;
      }
      if (flag(p, "--dry-run")) out(`Would set ${parsed.pairs.map(([n, r]) => `${n} from ${r}`).join(", ")} (values are read only when it starts).`);
      else {
        const { trustedApproverKey } = await import("./hook/pipeline.js");
        const { defaultBackendFor } = await import("./runtime/vault/substitute.js");
        const { randomBytes } = await import("node:crypto");
        const got = resolveRunEnv(l, { pairs: parsed.pairs, argv: p.positionals, ...(program !== null ? { program } : {}), workspace: resolve(opt(p, "--workspace") ?? process.cwd()), trustedKey: trustedApproverKey(l, baseEnv), backendFor: runOverrides.backendFor ?? defaultBackendFor(l), runId: randomBytes(6).toString("hex") });
        if (!got.ok) {
          err(`launchsafe-firewall run: refused: ${got.why}`);
          return EXIT_VAULT_DENIED;
        }
        extraEnv = got.env;
      }
    }
    const r = await runSandboxed({
      ...(extraEnv !== undefined ? { extraEnv } : {}),
      layout: l,
      command,
      passEnv: p.lists?.get("--pass-env") ?? [],
      allowHomeRead: p.lists?.get("--allow-home-read") ?? [],
      workspace: resolve(opt(p, "--workspace") ?? process.cwd()),
      allowWrite: list("--allow-write"),
      sendHosts: list("--send-host"),
      allowLocalhost: flag(p, "--allow-localhost"),
      allowKeychain: flag(p, "--allow-keychain"),
      gitInit: flag(p, "--git-init"),
      ...(opt(p, "--agent") !== undefined ? { agent: opt(p, "--agent") as "claude" | "codex" | "gemini" } : {}),
      dryRun: flag(p, "--dry-run"),
      verbose: flag(p, "--verbose"),
      env: process.env,
      home: homedir(),
      cwd: process.cwd(),
      say: out,
      warn: err,
    });
    return r.exitCode;
  },
  async demo() {
    const { runDemo } = await import("./demo.js");
    out(runDemo());
    return 0;
  },
  async version() {
    out(VERSION);
    return 0;
  },
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "serve" || c.path[0] === "api").map((c) => [c.path.join(" "), apiCommand(c.path.join(" "))])),
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "hosts").map((c) => [c.path.join(" "), hostsCommand(c.path.join(" "))])),
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "openshell").map((c) => [c.path.join(" "), openshellCommand(c.path.join(" "))])),
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "vault").map((c) => [c.path.join(" "), vaultCommand(c.path.join(" "))])),
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "scratch").map((c) => [c.path.join(" "), scratchCommand(c.path.join(" "))])),
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "mcp" || c.path[0] === "gateway").map((c) => [c.path.join(" "), gatewayCommand(c.path.join(" "))])),
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "mail").map((c) => [c.path.join(" "), mailCommand(c.path.join(" "))])),
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "phone" || c.path[0] === "relay").map((c) => [c.path.join(" "), phoneCommand(c.path.join(" "))])),
  ...Object.fromEntries(COMMANDS.filter((c) => c.path[0] === "session" || c.path[0] === "agent").map((c) => [c.path.join(" "), sessionCommand(c.path.join(" "))])),
  async help(p) {
    const target = p.positionals.length === 0 ? null : (COMMANDS.filter((s) => s.path.every((x, i) => p.positionals[i] === x)).sort((a, b) => b.path.length - a.path.length)[0] ?? null);
    if (p.positionals.length > 0 && target === null) {
      err(helpText(null));
      return EXIT_USAGE;
    }
    out(helpText(target));
    return 0;
  },
};

export function handlerKey(spec: CommandSpec): string {
  return spec.path.join(" ");
}

/** In-process callers (tests): capture output and stand in for the person-at-keyboard check. */
export interface MainOptions {
  write?: (fd: 1 | 2, s: string) => void;
  humanAtKeyboard?: () => Promise<boolean>;
  /** A fake store, scripted input and a platform for the vault's commands. */
  vault?: Partial<VaultCliDeps>;
  /** Scripted input for the email guard's commands. */
  mail?: Partial<MailCliDeps>;
  /** A stub relay, scripted input and a fake service manager for the phone commands. */
  phone?: Partial<PhoneCliDeps>;
  /** The vault store and environment for run --env (tests). */
  run?: RunOverrides;
  /** Scripted passphrase input (tests). */
  readSecret?: (prompt: string) => Promise<string>;
  /** Scripted passphrase input for the scratch commands. */
  scratch?: Partial<import("./scratch-cli.js").ScratchCliDeps>;
  /** Scripted input (the passphrase) and environment for session and agent stop/resume. */
  session?: Partial<SessionCliDeps>;
  /** Scripted input for the learned-choice commands (tests). */
  learned?: Partial<LearnedCliDeps>;
  /** Standard input from this descriptor, with this bound in place of MAX_STDIN_BYTES (tests). */
  stdin?: { fd: number; max?: number };
  /** The platform the support check sees, in place of process.platform (tests). */
  platform?: NodeJS.Platform;
}

/** Runs one command line. Parsing happens first; nothing runs on --help or a usage error. */
export async function main(argv: readonly string[], l: Layout = layout(), o: MainOptions = {}): Promise<number> {
  const before = { write, keyboardCheck, vaultOverrides, mailOverrides, phoneOverrides, runOverrides, secretReader, scratchOverrides, sessionOverrides, learnedOverrides, stdinOverride, platformOverride };
  if (o.stdin !== undefined) stdinOverride = o.stdin;
  if (o.platform !== undefined) platformOverride = o.platform;
  if (o.readSecret !== undefined) secretReader = o.readSecret;
  if (o.write !== undefined) write = o.write;
  if (o.humanAtKeyboard !== undefined) keyboardCheck = o.humanAtKeyboard;
  if (o.vault !== undefined) vaultOverrides = o.vault;
  if (o.mail !== undefined) mailOverrides = o.mail;
  if (o.phone !== undefined) phoneOverrides = o.phone;
  if (o.run !== undefined) runOverrides = o.run;
  if (o.scratch !== undefined) scratchOverrides = o.scratch;
  if (o.session !== undefined) sessionOverrides = o.session;
  if (o.learned !== undefined) learnedOverrides = o.learned;
  try {
    return await run(argv, l);
  } finally {
    write = before.write;
    keyboardCheck = before.keyboardCheck;
    vaultOverrides = before.vaultOverrides;
    scratchOverrides = before.scratchOverrides;
    mailOverrides = before.mailOverrides;
    phoneOverrides = before.phoneOverrides;
    runOverrides = before.runOverrides;
    secretReader = before.secretReader;
    sessionOverrides = before.sessionOverrides;
    learnedOverrides = before.learnedOverrides;
    stdinOverride = before.stdinOverride;
    platformOverride = before.platformOverride;
  }
}

async function run(argv: readonly string[], l: Layout): Promise<number> {
  const p = parseCommandLine(argv);
  const isHook = argv[0] === "hook";
  if (p.kind === "help") {
    out(helpText(p.spec));
    return 0;
  }
  if (p.kind === "error") {
    // The hook keeps its fail-closed contract: a bad invocation blocks the tool (exit 2), never 64.
    if (isHook) {
      err(`LaunchSafe Firewall: the hook command is malformed (${p.message}), so the action was blocked. Run "launchsafe-firewall doctor".`);
      return 2;
    }
    if (p.spec === null) {
      err(usageError(p));
      err("");
      err(helpText(null));
    } else err(usageError(p));
    return EXIT_USAGE;
  }
  // Before any handler runs: an unsupported platform reads and writes nothing, and the hook blocks the action.
  const refused = platformRefusal(p.spec);
  if (refused !== null) return refused;
  const h = own(HANDLERS, handlerKey(p.spec));
  if (h === undefined) {
    err(`launchsafe-firewall: no handler for "${handlerKey(p.spec)}"`);
    return isHook ? 2 : EXIT_USAGE;
  }
  return h(p, l);
}
