/**
 * Fuzz: the shell analyzer through the decision engine (test/helpers.ts bash()).
 * Properties: never throws; fails closed (an unparseable command is never a silent allow, and a dangerous
 * command followed or preceded by garbage is still not allowed); bounded time; deterministic.
 */
import { describe, expect, it } from "vitest";
import { bash, explain, type RunOpts } from "../helpers.js";
import { BENIGN_SHELL, DANGEROUS_SHELL } from "./corpus.js";
import { allowLongRuns, budget, fuzz, iters, mutateStringN, timed, SEVERITY, type Rng } from "./gen.js";

allowLongRuns();

/** The first frames of an error's stack inside src/ (where it came from). */
function where(e: unknown): string {
  return String((e as Error).stack).split("\n").filter((l) => l.includes("/src/")).slice(0, 3).map((l) => l.trim().replace(/^at /, "").replace(/.*\/src\//, "src/")).join(" < ");
}


const SHELL_BUDGET_MS = budget(400);
const STATES: RunOpts[] = [{}, { tainted: true }, { ctx: { interactive: false } }, { tainted: true, ctx: { interactive: false } }];

function sameDecision(a: ReturnType<typeof bash>, b: ReturnType<typeof bash>): boolean {
  return a.verdict === b.verdict && a.actionHash === b.actionHash && JSON.stringify(a.rules) === JSON.stringify(b.rules) && JSON.stringify(a.reasons) === JSON.stringify(b.reasons) && JSON.stringify(a.effects) === JSON.stringify(b.effects);
}

function command(r: Rng): string {
  const pool = r.bool(0.7) ? BENIGN_SHELL : DANGEROUS_SHELL;
  return mutateStringN(r, r.pick(pool), 5);
}

describe("fuzz: shell analyzer", () => {
  it("the dangerous seeds are not silent allows to begin with", () => {
    for (const c of DANGEROUS_SHELL) for (const o of STATES) expect(bash(c, o).verdict, `${c} ${JSON.stringify(o)}`).not.toBe("allow");
  });

  it("never throws, is deterministic, and decides within the time budget", () => {
    fuzz("shell:robust", iters(1), (r) => {
      const cmd = command(r);
      const o = r.pick(STATES);
      const label = `command=${JSON.stringify(cmd.length > 200 ? `${cmd.slice(0, 200)}...(${cmd.length} chars)` : cmd)}`;
      let d1: ReturnType<typeof bash>;
      let ms: number;
      try {
        ({ value: d1, ms } = timed(() => bash(cmd, o), SHELL_BUDGET_MS));
      } catch (e) {
        throw new Error(`threw ${(e as Error).message.replace(/(.)\1{30,}/gs, "$1...").slice(0, 80)} at ${where(e)}: ${label}`, { cause: e });
      }
      if (ms > SHELL_BUDGET_MS) throw new Error(`slow (${Math.round(ms)} ms > ${SHELL_BUDGET_MS}): ${label}`);
      if (!(d1.verdict in SEVERITY)) throw new Error(`no verdict: ${label}`);
      const d2 = bash(cmd, o);
      if (!sameDecision(d1, d2)) throw new Error(`not deterministic: ${label} first=${explain(d1)} second=${explain(d2)}`);
    });
  });

  it("an unparseable or unanalyzable command is never a silent allow", () => {
    fuzz("shell:parse-failure", iters(1), (r) => {
      const cmd = command(r);
      const o = r.pick(STATES);
      const d = bash(cmd, o);
      const blind = d.findings.some((f) => f.id === "parse_failure" || f.id === "too_large");
      if (blind && d.verdict === "allow") throw new Error(`allow despite ${d.findings.map((f) => f.id).join(",")}: command=${JSON.stringify(cmd.slice(0, 200))} ${explain(d)}`);
    });
  });

  it("a dangerous command stays stopped when garbage comes before or after it", () => {
    fuzz("shell:dangerous+garbage", iters(1), (r) => {
      const danger = r.pick(DANGEROUS_SHELL);
      const junk = mutateStringN(r, r.pick(BENIGN_SHELL), 4);
      const sep = r.pick([" ; ", "\n", " && ", " || ", " ; # ", "\n\n"]);
      const cmd = r.bool() ? `${junk}${sep}${danger}` : `${danger}${sep}${junk}`;
      // `a || danger` and `danger # junk` can legitimately not run the dangerous part; `;`, `&&`, newline do.
      if (cmd.includes("||") && !cmd.startsWith(danger)) return;
      if (sep.includes("#") && !cmd.startsWith(danger)) return;
      // A "#" in the garbage before the command comments out the rest of its line.
      if (!cmd.startsWith(danger) && junk.includes("#") && !sep.includes("\n")) return;
      // An odd run of backslashes ending the garbage escapes the one newline after it: an unquoted
      // backslash-newline pair is a line continuation, removed from the input (bash manual, 3.1.2.1 Escape
      // Character), so the dangerous command becomes the garbage command's arguments and never runs on its own
      // (shell:dangerous+garbage seed 102823: 53 backslashes). An even run is literal backslashes; the newline
      // still ends the command, and that case stays checked.
      if (!cmd.startsWith(danger) && sep === "\n" && /(?:^|[^\\])(?:\\\\)*\\$/.test(junk)) return;
      const o = r.pick(STATES);
      const d = bash(cmd, o);
      if (d.verdict === "allow") throw new Error(`allowed ${JSON.stringify(danger)} behind garbage: command=${JSON.stringify(cmd.slice(0, 300))} ${explain(d)}`);
    });
  });

  it("wrapping or prefixing a dangerous command does not lower its verdict", () => {
    fuzz("shell:wrap", iters(1), (r) => {
      const danger = r.pick(DANGEROUS_SHELL);
      const wrapped = r.pick([`sudo ${danger}`, `env X=1 ${danger}`, `timeout 5 ${danger}`, `nohup ${danger}`, `time ${danger}`, `(${danger})`, `{ ${danger}; }`, `if true; then ${danger}; fi`, `for i in 1; do ${danger}; done`, `bash -c ${JSON.stringify(danger)}`, `sh -c '${danger.replace(/'/g, "")}'`, `$(${danger})`, `\`${danger}\``]);
      const o = r.pick(STATES);
      const d = bash(wrapped, o);
      if (d.verdict === "allow") throw new Error(`allowed wrapped ${JSON.stringify(danger)}: command=${JSON.stringify(wrapped)} ${explain(d)}`);
    });
  });

  it("a dangerous command is never allowed inside any executing shell construct, nested", () => {
    const q = (x: string): string => `'${x.replace(/'/g, `'\\''`)}'`;
    const simple = (c: string): boolean => !/[;&|(){}\n<>]/.test(c);
    // A benign command put on the same line before the dangerous one must not open a here-document: bash reads
    // a here-document's body "until a line containing only word (with no trailing blanks) is seen" (bash manual,
    // 3.6.6 Here Documents), so in `cat <<'EOF'\n...\nEOF || danger` the line `EOF || danger` is body text and
    // never runs (shell:grammar seed 151719 was this oracle's false positive, not an analyzer miss).
    const before = (r: Rng): string => r.pick(BENIGN_SHELL.filter((b) => !/<<(?!<)/.test(b)));
    const wrap = (r: Rng, inner: string): string => {
      let k = r.int(22);
      // A prefix such as sudo or exec only takes a simple command.
      if ((k === 6 || k === 17) && !simple(inner)) k = 10;
      if (k === 15 && inner.includes("`")) k = 10;
      if (k === 20 && inner.includes('"')) k = 10;
      switch (k) {
        case 0: return `${inner}; ${r.pick(BENIGN_SHELL)}`;
        case 1: return `${before(r)}; ${inner}`;
        case 2: return `${before(r)} && ${inner}`;
        case 3: return `${before(r)} || ${inner}`;
        case 4: return `${inner} | ${r.pick(["cat", "tee /dev/null", "head -1"])}`;
        case 5: return `${r.pick(BENIGN_SHELL)}\n${inner}\n`;
        case 6: return `${r.pick(["sudo", "env X=1", "timeout 5", "nohup", "time", "command", "exec", "nice", "stdbuf -o0"])} ${inner}`;
        case 7: return `bash -c ${q(inner)}`;
        case 8: return `sh -c ${q(inner)}`;
        case 9: return `eval ${q(inner)}`;
        case 10: return `( ${inner} )`;
        case 11: return `{ ${inner}; }`;
        case 12: return `if true; then ${inner}; fi`;
        case 13: return `for i in 1 2; do ${inner}; done`;
        case 14: return `echo $( ${inner} )`;
        case 15: return `echo \`${inner}\``;
        case 16: return `${inner} &`;
        case 17: return `! ${inner}`;
        case 18: return `case x in x) ${inner} ;; esac`;
        case 19: {
          const n = r.pick(["f", "run_it"]);
          return `${n}${r.pick(["()", " ()"])} { ${inner}; }; ${n}`;
        }
        case 20: return `echo "$( ${inner} )"`;
        default: return `until false; do ${inner}; break; done`;
      }
    };
    fuzz("shell:grammar", iters(1), (r) => {
      let cmd = r.pick(DANGEROUS_SHELL);
      const depth = r.range(1, 4);
      for (let i = 0; i < depth; i++) cmd = wrap(r, cmd);
      const o = r.pick(STATES);
      const d = bash(cmd, o);
      if (d.verdict === "allow") throw new Error(`allowed a dangerous command inside constructs: command=${JSON.stringify(cmd.slice(0, 400))} ${explain(d)}`);
    });
  });
});

