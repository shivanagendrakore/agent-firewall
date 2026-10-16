/**
 * Final independent enforcement review (11 Oct 2026) of two fix rounds before the public release:
 *
 *  A. the shell recheck: scripts a shell reads from standard input, `source` of computed paths, wrapper option
 *     tables, run-time paths under xargs / find -exec / fd -x / parallel, here-document line continuations;
 *  B. the decision-log hardening: bounded events, the fallback entry, FW-LOG-UNRECORDED, the gateway
 *     wrapper's NODE_COMPILE_CACHE, and the gateway's task / _meta forwarding.
 *
 * Each test states correct behaviour. Where the code does not hold, the test is `it.fails` with a one-line
 * reason (LR-numbered), so it turns red when the gap is fixed. Shell decisions are made only through the
 * analyzer (bash()/explain()); no sample command ever reaches a shell. Temporary homes only.
 */

import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { boundEvent, appendBounded, MAX_FIELD_CHARS } from "../../src/runtime/logbound.js";
import { loadKey, MAX_TAIL_SEARCH, tailLog, verifyLog } from "../../src/runtime/log.js";
import { installDir, layout, type Layout } from "../../src/runtime/layout.js";
import { runHook } from "../../src/hook/claude.js";
import { applyPlan, clientFiles, planWrap, wrappedWithoutCompileCache } from "../../src/gateway/clients.js";
import { doctor } from "../../src/runtime/doctor.js";
import { createNodeGuard, fileStore } from "../../src/sdk/node.js";
import type { Json } from "../../src/gateway/jsonrpc.js";
import { gw, newHome, type Gw } from "../gateway/harness.js";
import { bash, explain, tempHome } from "../helpers.js";

// --- shell helpers ------------------------------------------------------------------------------------

/** Never a plain allow, trusted or untrusted. */
function caught(cmd: string): void {
  for (const tainted of [false, true]) {
    const d = bash(cmd, { tainted });
    expect(d.verdict, `${tainted ? "untrusted" : "trusted"}: ${explain(d)}`).not.toBe("allow");
  }
}
/** At least asked once the session is untrusted (the minimum for code or a program the firewall cannot see). */
function notAllowedUntrusted(cmd: string): void {
  const d = bash(cmd, { tainted: true });
  expect(d.verdict, explain(d)).not.toBe("allow");
}
/** The same verdict as the reference, trusted and untrusted, and not an allow. */
function sameAs(cmd: string, ref: string): void {
  for (const tainted of [false, true]) {
    const d = bash(cmd, { tainted });
    const r = bash(ref, { tainted });
    expect(d.verdict, `${explain(d)}\n  reference: ${explain(r)}`).toBe(r.verdict);
    expect(d.verdict).not.toBe("allow");
  }
}
/** Untrusted: the same verdict as the reference, and not an allow (for code a trusted session may run unseen). */
function sameUntrusted(cmd: string, ref: string): void {
  const d = bash(cmd, { tainted: true });
  const r = bash(ref, { tainted: true });
  expect(d.verdict, `${explain(d)}\n  reference: ${explain(r)}`).toBe(r.verdict);
  expect(d.verdict).not.toBe("allow");
}
const allowed = (cmd: string): void => {
  for (const tainted of [false, true]) {
    const d = bash(cmd, { tainted });
    expect(d.verdict, explain(d)).toBe("allow");
  }
};

// =====================================================================================================
// A. Shell recheck
// =====================================================================================================

describe("A holds: wrapper option tables, clusters, -- and chains", () => {
  const forms = [
    "nice -n5 -- rm -rf ~",
    "timeout -- 5 rm -rf ~",
    "timeout -sKILL 5 rm -rf ~",
    "env -- rm -rf ~",
    "env -i -- FOO=1 rm -rf ~",
    "env -iS'rm -rf ~'",
    "env --split-string='rm -rf ~'",
    "env -S 'rm -rf /Users/dev'",
    "exec -a foo -- rm -rf ~",
    "caffeinate -dimsu rm -rf ~",
    "time -- rm -rf ~",
    "ionice -c2 -n7 rm -rf ~",
    "taskset -- 0x1 rm -rf ~",
    "chrt -r -- 10 rm -rf ~",
    "setsid -- rm -rf ~",
    "sudo -uroot rm -rf ~",
    "sudo -- rm -rf ~",
    "doas -- rm -rf ~",
    "pkexec --user root rm -rf ~",
    "run0 -u root rm -rf ~",
    "nohup sudo -u root rm -rf ~",
    "command exec nice rm -rf ~",
    "nice nohup timeout 5 env -i stdbuf -oL xargs -0 rm -rf ~",
    "xargs -o rm -rf ~",
    "xargs -Jx rm -rf x ~",
    "xargs -l rm -rf ~",
    "xargs --max-lines rm -rf ~",
    "xargs --process-slot-var=V rm -rf ~",
    "xargs --delim=x rm -rf ~",
    "xargs --no-run rm -rf ~",
    "parallel --bar --jobs 2 rm -rf ::: '~'",
    "parallel --halt now,fail=1 rm -rf ::: '~'",
    "parallel -j2 --tag rm -rf {} ::: '~'",
    "parallel --colsep , rm -rf {1} ::: '~'",
    "parallel -q rm -rf ::: '~'",
  ];
  for (const cmd of forms) it(JSON.stringify(cmd), () => caught(cmd));
});

describe("A holds: stdin scripts, here-document continuations, run-time paths", () => {
  const forms = [
    "bash -o posix <<< 'rm -rf ~'",
    "bash --norc --noprofile <<< 'rm -rf ~'",
    "bash -ex <<< 'rm -rf ~'",
    "bash -O extglob -s <<< 'rm -rf ~'",
    "echo 'rm -rf ~' | env bash",
    "echo 'rm -rf ~' | sudo bash",
    "echo 'rm -rf ~' | busybox sh",
    "echo 'rm -rf ~' | nice -n 5 bash",
    "echo 'rm -rf ~' | timeout 5 sh -s",
    "echo 'rm -rf ~' | fish",
    "echo 'rm -rf ~' | csh",
    "echo 'rm -rf ~' | xargs -0 bash -c",
    "echo 'rm -rf ~' | xargs -0 -I{} bash -c {}",
    "ls | xargs -I{} sh -c 'rm -rf {}'",
    "find . -exec sh -c 'rm -rf {}' ';'",
    "cat <<EOF\n$\\\n\\\n(rm -rf ~)\nEOF",
    "cat <<-EOF\n\t$\\\n(rm -rf ~)\nEOF",
    "cat <<EOF\n$\\\n{X:-$\\\n(rm -rf ~)}\nEOF",
    "cat <<EOF\n$(\\\nrm -rf ~)\nEOF",
    "cat <<EOF\n$((1+$\\\n(rm -rf ~)))\nEOF",
    "xargs -0I{} rm -rf {}",
    "xargs -a list rm -rf",
    "xargs --arg-file=list rm -rf",
    "xargs -R 2 -I x rm -rf x",
    "find . -exec rm -rf {} \\;",
    "find . -exec rm -rf {} x +",
    "find ~ -maxdepth 0 -execdir rm -rf {} +",
    "find ~ -okdir rm -rf {} +",
    "parallel -a list rm -rf",
  ];
  for (const cmd of forms) it(JSON.stringify(cmd), () => caught(cmd));
});

describe("A holds: everyday commands stay allowed", () => {
  const fine = [
    "git ls-files -z | xargs -0 npx prettier --check",
    "find . -type f -exec sha256sum {} +",
    "find . -name '*.ts' -exec grep -n TODO {} ';'",
    "fd -e ts -x wc -l",
    "xargs -0 -n1 basename < files.txt",
    "nice -n 19 make -j8",
    "timeout -s INT 10 npm test",
    "env -S 'npm test'",
    "ionice -c3 npm run build",
    "bash -o pipefail -c 'npm test | tee out.log'",
    "bash -e <<< 'npm test'",
    "echo 'ls -la' | bash -s",
    "cat <<'EOF' | sh\nnpm run lint\nEOF",
    "parallel gzip -k ::: a.log b.log",
    "ls *.md | parallel wc -l",
  ];
  for (const cmd of fine) it(JSON.stringify(cmd), () => allowed(cmd));
});

describe("LR1: program-running wrappers missing from the wrapper table", () => {
  // Each runs the words after it (or a string) as a command; the analyzer treats it as an unknown program and
  // never looks at `rm -rf ~`, so the home directory's deletion is allowed even in an untrusted session.
  const forms = [
    "genv rm -rf ~",
    "gnice rm -rf ~",
    "gnohup rm -rf ~",
    "gstdbuf -oL rm -rf ~",
    "gxargs rm -rf ~",
    "gfind ~ -delete",
    "sem rm -rf ~",
    "fakeroot rm -rf ~",
    "xvfb-run rm -rf ~",
    "dbus-run-session rm -rf ~",
    "direnv exec . rm -rf ~",
    "unshare -r rm -rf ~",
    "chroot / rm -rf ~",
    "nsenter -t 1 rm -rf ~",
    "runuser -u dev -- rm -rf ~",
    "prlimit --nofile=10 rm -rf ~",
    "numactl -N0 rm -rf ~",
    "firejail rm -rf ~",
    "bwrap --bind / / rm -rf ~",
    "watchexec -- rm -rf ~",
    "hyperfine 'rm -rf ~'",
    "nodemon --exec 'rm -rf ~'",
  ];
  for (const cmd of forms) it.fails(`${JSON.stringify(cmd)} (LR1: wrapper not modelled, inner rm -rf ~ unseen, allowed untrusted)`, () => notAllowedUntrusted(cmd));
});

describe("LR2: env -S escape sequences", () => {
  // GNU and BSD env -S treat `\_` outside quotes as an argument separator: this runs `rm -rf /Users/dev`.
  // The analyzer parses the string as shell, reads `rm_-rf_/Users/dev` as one program name and allows it.
  it.fails("env -S 'rm\\_-rf\\_/Users/dev' is the same as rm -rf /Users/dev (LR2: \\_ separator not honoured, allowed untrusted)", () => {
    sameAs("env -S 'rm\\_-rf\\_/Users/dev'", "rm -rf /Users/dev");
  });
});

describe("LR3: a shell's +option is taken as its script", () => {
  // `bash +x`, `sh +o posix`, `zsh +f` are options; the script still comes from stdin (or the next word).
  it.fails("bash +x <<< 'rm -rf ~' (LR3: +x read as the script file, stdin script never analysed)", () => caught("bash +x <<< 'rm -rf ~'"));
  it.fails("echo 'rm -rf ~' | bash +x (LR3)", () => caught("echo 'rm -rf ~' | bash +x"));
  it.fails("sh +o posix <<< 'rm -rf ~' (LR3)", () => caught("sh +o posix <<< 'rm -rf ~'"));
  it.fails("zsh +f <<< 'rm -rf ~' (LR3)", () => caught("zsh +f <<< 'rm -rf ~'"));
  it.fails("bash +x ~/Downloads/evil.sh is judged like bash ~/Downloads/evil.sh (LR3: the downloaded script is not the one judged)", () => {
    sameAs("bash +x /Users/dev/Downloads/evil.sh", "bash /Users/dev/Downloads/evil.sh");
  });
});

describe("LR4: /dev/fd/0 and /proc/self/fd/0 are standard input", () => {
  it.fails("bash /dev/fd/0 <<< 'rm -rf ~' (LR4: only - and /dev/stdin are read as stdin)", () => caught("bash /dev/fd/0 <<< 'rm -rf ~'"));
  it.fails("bash /proc/self/fd/0 <<< 'rm -rf ~' (LR4)", () => caught("bash /proc/self/fd/0 <<< 'rm -rf ~'"));
  it.fails("source /dev/fd/0 <<< 'rm -rf ~' (LR4)", () => caught("source /dev/fd/0 <<< 'rm -rf ~'"));
});

describe("LR5: interpreters reading their script from a pipe or <", () => {
  it("holds: a here-string to python3 is read as its code (asked untrusted, like python3 -c)", () => {
    notAllowedUntrusted("python3 <<< \"import os; os.system('rm -rf ~')\"");
  });
  it.fails("echo '<code>' | python3 is judged like python3 -c '<code>' (LR5: piped static text not analysed, no opaque effect)", () => {
    sameUntrusted("echo \"import os; os.system('rm -rf ~')\" | python3", "python3 -c \"import os; os.system('rm -rf ~')\"");
  });
  it.fails("echo '<code>' | node is judged like node -e '<code>' (LR5)", () => {
    sameUntrusted("echo \"require('child_process').execSync('rm -rf ~')\" | node", "node -e \"require('child_process').execSync('rm -rf ~')\"");
  });
  it.fails("python3 < ~/Downloads/evil.py is judged like python3 ~/Downloads/evil.py (LR5: < to an interpreter is a plain read)", () => {
    sameAs("python3 < /Users/dev/Downloads/evil.py", "python3 /Users/dev/Downloads/evil.py");
  });
  it.fails("node --input-type commonjs <<< '<code>' reads the here-string as code (LR5: the option's value is taken as the script)", () => {
    notAllowedUntrusted("node --input-type commonjs <<< \"require('child_process').execSync('rm -rf ~')\"");
  });
});

describe("LR6: a run-time path as the program", () => {
  // xargs -I / parallel / find -exec put each input where the replacement string is; as the first word it is
  // the program itself, known only at run time. It is judged as a program literally called "{}".
  it.fails("echo rm | xargs -I{} {} -rf /Users/dev (LR6: executed as the literal program {}, allowed untrusted)", () => notAllowedUntrusted("echo rm | xargs -I{} {} -rf /Users/dev"));
  it.fails("echo rm | parallel {} -rf /Users/dev (LR6)", () => notAllowedUntrusted("echo rm | parallel {} -rf /Users/dev"));
  it.fails("find . -exec {} ';' (LR6)", () => notAllowedUntrusted("find . -exec {} ';'"));
  it.fails("ls | xargs -I@ @ (LR6)", () => notAllowedUntrusted("ls | xargs -I@ @"));
});

describe("LR7: fd short-option clusters hide -x / -X", () => {
  it("holds: fd . -x rm -rf asks like rm -rf on a run-time path", () => sameAs("fd . -x rm -rf", 'rm -rf "$X"'));
  it.fails("fd -tdx rm -rf is judged like fd -td -x rm -rf (LR7: only a separate -x word is found)", () => sameAs("fd -tdx rm -rf", "fd -td -x rm -rf"));
  it.fails("fd . /Users/dev -Hx rm -rf (LR7: deletes everything under home, allowed untrusted)", () => caught("fd . /Users/dev -Hx rm -rf"));
});

describe("LR8: find -exec's + ends the command only right after {}", () => {
  // find: `+` terminates -exec only when it follows `{}`; otherwise it is an argument. This runs `rm -rf + <path>`.
  it.fails("find . -exec rm -rf + {} ';' is judged like find . -exec rm -rf {} ';' (LR8: the sub-command is cut at the first +)", () => {
    sameAs("find . -exec rm -rf + {} ';'", "find . -exec rm -rf {} ';'");
  });
});

describe("LR9: xargs hands run-time paths to programs that write", () => {
  it("holds: the find -exec form has a known root and asks", () => notAllowedUntrusted("find ~ -type f -exec truncate -s 0 {} +"));
  it.fails("find ~ -type f | xargs truncate -s 0 asks like truncate -s 0 \"$X\" (LR9: only deleters and runners get the run-time path)", () => {
    notAllowedUntrusted("find ~ -type f | xargs truncate -s 0");
  });
});

describe("LR10: parallel --pipe feeds standard input to the command", () => {
  it.fails("echo 'rm -rf ~' | parallel --pipe bash is judged like echo 'rm -rf ~' | bash (LR10: opaque, so allowed in a trusted session)", () => {
    sameAs("echo 'rm -rf ~' | parallel --pipe bash", "echo 'rm -rf ~' | bash");
  });
});

// =====================================================================================================
// B. Decision log
// =====================================================================================================

const currentLog = (l: Layout): string => join(l.log, "decisions.jsonl");
const breakLog = (l: Layout): void => appendFileSync(currentLog(l), `${"q".repeat(MAX_TAIL_SEARCH + 5)}\n`);
const rawEvents = (l: Layout): Record<string, unknown>[] =>
  readFileSync(currentLog(l), "utf8")
    .split("\n")
    .flatMap((line) => {
      try {
        const e = JSON.parse(line) as { event?: Record<string, unknown> };
        return e.event !== undefined ? [e.event] : [];
      } catch {
        return [];
      }
    });

function hookCall(home: string, l: Layout, tool: string, input: Json): { decision: string | undefined; stderr: string } {
  const ws = join(home, "proj");
  const ev = { hook_event_name: "PreToolUse", session_id: "lr", cwd: ws, permission_mode: "default", tool_name: tool, tool_input: input };
  const r = runHook(JSON.stringify(ev), { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, home, scratchRoots: [join(home, "scratch")], detectNonInteractive: () => true });
  let decision: string | undefined = r.exitCode === 2 ? "deny" : r.exitCode === 0 ? "allow" : undefined;
  try {
    decision = (JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string } }).hookSpecificOutput?.permissionDecision ?? decision;
  } catch {
    // The exit code decides.
  }
  return { decision, stderr: r.stderr };
}

describe("B holds: bounded fields keep different actions distinguishable", () => {
  it("two hook decisions whose commands differ only after the bounded prefix log different action hashes, and verify", () => {
    const home = tempHome("lr-b-");
    const l = layout(join(home, ".launchsafe-firewall"));
    const base = `echo ${"a".repeat(MAX_FIELD_CHARS * 2)}`;
    hookCall(home, l, "Bash", { command: `${base} one` });
    hookCall(home, l, "Bash", { command: `${base} two` });
    const ds = tailLog(l, 100).filter((e) => e.event.type === "decision");
    expect(ds).toHaveLength(2);
    expect(ds[0]?.event.action).toMatch(/^[0-9a-f]{64}$/);
    expect(ds[0]?.event.action).not.toBe(ds[1]?.event.action);
    expect(verifyLog(l).problems).toEqual([]);
  });

  it("strings that differ past the cut keep different sha256 notes; long keys that share a prefix stay distinct", () => {
    const a = boundEvent({ type: "x", v: `${"z".repeat(MAX_FIELD_CHARS)}A`, [`${"k".repeat(200)}1`]: 1, [`${"k".repeat(200)}2`]: 2 });
    const b = boundEvent({ type: "x", v: `${"z".repeat(MAX_FIELD_CHARS)}B` });
    expect(a.v).toBe(b.v);
    const sha = (e: Record<string, unknown>): string => ((e.bounded as { fields: { field: string; sha256: string }[] }).fields.find((f) => f.field === "v")?.sha256 ?? "");
    expect(sha(a)).not.toBe(sha(b));
    expect(Object.keys(a).filter((k) => k.startsWith("kkk"))).toHaveLength(2);
  });

  it("the fallback entry for an event over the cap keeps verdict, rules and action, and the log verifies", () => {
    const l = layout(join(tempHome("lr-f-"), "fw"));
    loadKey(l);
    const huge: Record<string, unknown> = { type: "decision", verdict: "allow", rules: ["FW-X"], action: "b".repeat(64), session: "s" };
    for (let i = 0; i < 64; i++) huge[`k${i}`] = Array.from({ length: 64 }, () => "y".repeat(MAX_FIELD_CHARS));
    const e = appendBounded(l, huge);
    expect(e.event).toMatchObject({ type: "decision", fallback: true, verdict: "allow", rules: ["FW-X"], action: "b".repeat(64), session: "s", refused: "size" });
    expect(verifyLog(l).ok).toBe(true);
  });

  it("hook: an allowed read whose decision cannot be recorded is not let through (FW-LOG-UNRECORDED)", () => {
    const home = tempHome("lr-h-");
    const l = layout(join(home, ".launchsafe-firewall"));
    const read = { file_path: join(home, "proj", "a.txt") };
    expect(hookCall(home, l, "Read", read).decision).toBe("allow");
    breakLog(l);
    const after = hookCall(home, l, "Read", read);
    expect(after.decision).toBe("deny");
  });
});

describe("LR11: the SDK guard carries out decisions the log refused", () => {
  function tree(): { ws: string; home: string; scratch: string; fw: string } {
    const root = tempHome("lr-sdk-");
    const t = { ws: join(root, "workspace"), home: join(root, "home"), scratch: join(root, "scratch"), fw: join(root, "state") };
    for (const d of [t.ws, t.home, t.scratch]) mkdirSync(d, { recursive: true });
    return t;
  }
  it("decide() on an allowed call with the log refusing every entry does not return allow (LR11: fixed; the guard and fileStore use the bounded path and fail closed)", () => {
    const t = tree();
    const g = createNodeGuard({ session: "lr11", workspace: t.ws, home: t.home, scratch: [t.scratch], attended: false, tools: { read_ticket: { kind: "read" } }, store: fileStore({ home: t.fw }) });
    expect(g.decide({ tool: "read_ticket", input: { id: "1" } }).verdict).toBe("allow");
    breakLog(layout(t.fw));
    const d = g.decide({ tool: "read_ticket", input: { id: "2" } });
    expect(d.verdict).not.toBe("allow");
  });
});

describe("LR12: gateway input requests passed on when their log entry is refused", () => {
  it("an elicitation input request from the server is not passed to the client unrecorded (LR12: fixed; refused with FW-LOG-UNRECORDED)", () => {
    const { l, home } = newHome();
    const ref: { g?: Gw } = {};
    let broken = false;
    const cfg = (): Json => {
      // Break the log once the call has been decided, logged and forwarded: its answer comes back next.
      if (!broken && ref.g !== undefined && ref.g.up.received[ref.g.up.received.length - 1]?.method === "tools/call") {
        broken = true;
        breakLog(l);
      }
      return { era: "modern", tools: [{ name: "search", description: "Search.", inputSchema: { type: "object" } }], inputRequired: { search: { resultType: "input_required", inputRequests: { e1: { method: "elicitation/create", params: { mode: "form", message: "Pick one", requestedSchema: { type: "object", properties: {} } } } }, requestState: "abc" } } };
    };
    const g = gw({ l, home, server: "notes", cfg: cfg as never });
    ref.g = g;
    g.call("tools/list");
    const r = g.call("tools/call", { name: "search", arguments: { q: "x" } });
    expect(broken).toBe(true);
    const passed = r.result?.inputRequests !== undefined;
    const logged = rawEvents(l).some((e) => e.type === "gateway_input_request" && e.passed === true);
    expect(!passed || logged).toBe(true);
  });
});

describe("B holds: doctor's gateway-wrapper check", () => {
  const fe = (home: string) => ({ home, platform: "darwin" as NodeJS.Platform, env: {} });
  const desktop = (home: string): string => join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  function write(p: string, text: string): void {
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, text);
  }
  function wrapDesktop(l: Layout, home: string): void {
    const plans = planWrap({ l, client: "claude-desktop" as Parameters<typeof clientFiles>[0], node: process.execPath, cli: join(installDir(), "dist", "cli.js"), port: 8473 }, fe(home));
    for (const p of plans) applyPlan(l, p);
  }

  it("a wrapped entry later edited to name a compile cache directory (or to drop the empty value) fails doctor", () => {
    const { l, home } = newHome();
    write(desktop(home), JSON.stringify({ mcpServers: { files: { command: "npx", args: ["files-mcp"] }, other: { command: "npx", args: ["other-mcp"] } } }));
    wrapDesktop(l, home);
    expect(wrappedWithoutCompileCache(l)).toEqual([]);
    const doc = JSON.parse(readFileSync(desktop(home), "utf8")) as { mcpServers: Record<string, { env?: Record<string, string> }> };
    (doc.mcpServers.files as { env: Record<string, string> }).env.NODE_COMPILE_CACHE = "/tmp/agent-writable";
    delete (doc.mcpServers.other as { env?: Record<string, string> }).env;
    write(desktop(home), JSON.stringify(doc));
    expect(wrappedWithoutCompileCache(l).map((x) => x.server).sort()).toEqual(["files", "other"]);
    const check = doctor(l, join(home, "ws"), { home, platform: "darwin", claudeVersion: "2.1.289" }).find((c) => c.name === "gateway wrapper");
    expect(check?.status).toBe("fail");
    expect(check?.detail).toMatch(/"files"/);
  });
});
