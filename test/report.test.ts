/**
 * The morning queue, `queue show` and `status`: readable, wrapped on word
 * boundaries, never cut mid-word, and `--json` keeps the full machine format.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { describeSource, ruleSentence, summarizeAction } from "../src/engine/summary.js";
import { runHook } from "../src/hook/claude.js";
import { layout } from "../src/runtime/layout.js";
import { formatQueue, formatShow, formatStatus, lineDiff, localTime, wrap } from "../src/runtime/report.js";
import { listQueue, recentSessions, type QueueItem } from "../src/runtime/store.js";
import { spawnCli } from "./helpers.js";

/** Every line fits, or is a single word that is longer than the width on its own. */
function fits(text: string, width: number): void {
  for (const line of text.split("\n")) {
    if (line.length > width) expect(line.trim().includes(" "), `line wider than ${width} and not a single word: "${line}"`).toBe(false);
  }
}

/** The words of the output are exactly the words of the input, in order: nothing cut, nothing lost. */
function sameWords(a: string, b: string): void {
  expect(b.split(/\s+/).filter(Boolean)).toEqual(a.split(/\s+/).filter(Boolean));
}

describe("wrap", () => {
  it("wraps on spaces within the width", () => {
    const t = "the quick brown fox jumps over the lazy dog";
    const lines = wrap(t, 15);
    expect(lines).toEqual(["the quick brown", "fox jumps over", "the lazy dog"]);
  });
  it("never splits a long word; it gets its own line", () => {
    const long = "https://collector.unknown-host.example/in?with=a-very-long-query-string";
    const lines = wrap(`send to ${long} now`, 20);
    expect(lines).toContain(long);
    sameWords(`send to ${long} now`, lines.join(" "));
  });
  it("indents continuation lines and keeps paragraphs", () => {
    expect(wrap("a b c\nd", 80, "  ")).toEqual(["  a b c", "  d"]);
  });
  it("property: no word is ever cut or lost, at any width", () => {
    let seed = 7;
    const rnd = (): number => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    for (let k = 0; k < 500; k++) {
      const words = Array.from({ length: 1 + Math.floor(rnd() * 40) }, () => "x".repeat(1 + Math.floor(rnd() * 30)));
      const text = words.join(" ");
      const width = 10 + Math.floor(rnd() * 100);
      const out = wrap(text, width).join("\n");
      sameWords(text, out);
      fits(out, width);
    }
  });
});

describe("summaries", () => {
  it("names what the agent wanted to do", () => {
    expect(summarizeAction("Bash", { command: "git push origin main" }, "/w")).toBe("Push commits to origin");
    expect(summarizeAction("Edit", { file_path: "/w/CLAUDE.md" }, "/w")).toBe("Change CLAUDE.md");
    expect(summarizeAction("Bash", { command: "curl -X POST https://x.example.com -d a" }, "/w", "send data to x.example.com (curl)")).toBe("Send data to x.example.com");
    expect(summarizeAction("mcp__github__create_pull_request", { owner: "a", repo: "b" }, "/w")).toBe("Create pull request (github) on a/b");
  });
  it("says where outside content came from", () => {
    expect(describeSource("read from gmail.read_message")).toBe("an email from gmail.read_message");
    expect(describeSource("read from slack.get_channel_history")).toBe("a message from slack.get_channel_history");
    expect(describeSource("read the web page https://example.com")).toBe("the web page https://example.com");
    expect(describeSource("read what curl brings back from example.com")).toBe("curl brings back from example.com");
  });
  it("gives one sentence per rule, and falls back to the first sentence of the reason", () => {
    expect(ruleSentence(["FW-SEND"], [])).toMatch(/^It sends data off this machine/);
    expect(ruleSentence(["FW-NEW-RULE"], ["thing: it is risky. More text."])).toBe("It is risky.");
  });
  it("formats local time like 3:14 AM", () => {
    const now = new Date(2026, 9, 9, 9, 0);
    expect(localTime(new Date(2026, 9, 9, 3, 14), now)).toBe("3:14 AM");
    expect(localTime(new Date(2026, 9, 8, 15, 5), now)).toBe("yesterday 3:05 PM");
    expect(localTime(new Date(2026, 9, 1, 3, 14), now)).toBe("Oct 1, 3:14 AM");
  });
});

const NOW = new Date(2026, 9, 9, 9, 0);
function item(over: Partial<QueueItem>): QueueItem {
  return {
    version: 1,
    id: "yayft9w6",
    createdAt: new Date(2026, 9, 9, 3, 14).toISOString(),
    sessionId: "night-3am",
    cwd: "/w",
    tool: "Bash",
    input: { command: "git push origin main" },
    actionHash: "9f3ac1d27be04455",
    rules: ["FW-SEND"],
    reasons: ['push commits to the git remote "origin": data leaves this machine. This session has read outside content (read from gmail.read_message), so it may be acting on someone else\'s instructions.'],
    kind: "approval",
    status: "pending",
    summary: "Push commits to origin",
    trustSources: ["read from gmail.read_message"],
    unattended: true,
    ...over,
  };
}

describe("formatQueue", () => {
  const items = [
    item({}),
    item({ id: "k2mfa8qe", tool: "Edit", kind: "proposal", rules: ["FW-INSTRUCTIONS-HELD"], summary: "Change CLAUDE.md", input: { file_path: "/w/CLAUDE.md" }, createdAt: new Date(2026, 9, 9, 3, 15).toISOString(), proposal: { target: "/w/CLAUDE.md", change: "x", edits: [{ old: "# acme-shop", new: "# acme-shop\n\nNotes added." }] } }),
  ];
  for (const width of [40, 60, 84, 120]) {
    it(`reads as a morning summary at width ${width}, wrapped, nothing cut`, () => {
      const out = formatQueue(items, { width, now: NOW });
      expect(out.split("\n")[0]).toBe("2 actions held while you were away");
      // The 6-character action code is the one the phone shows (actionHash.slice(0, 6)).
      expect(out.replace(/\s+/g, " ")).toContain("yayft9w6 · code 9f3ac1 · 3:14 AM · needs approval");
      expect(out.replace(/\s+/g, " ")).toContain("Push commits to origin");
      expect(out.replace(/\s+/g, " ")).toContain("It sends data off this machine, and the session had already read outside content.");
      expect(out.replace(/\s+/g, " ")).toContain("after reading: an email from gmail.read_message");
      expect(out.replace(/\s+/g, " ")).toContain("Change CLAUDE.md");
      expect(out).not.toMatch(/…|\.\.\.$/m);
      fits(out, width);
    });
  }
  it("singular header, and 'for your review' when a person was there", () => {
    expect(formatQueue([item({ unattended: false })], { width: 80, now: NOW }).split("\n")[0]).toBe("1 action held for your review");
  });
  it("an empty queue says so", () => expect(formatQueue([], { width: 80 })).toBe("Nothing is waiting for you."));
  it("older items without the new fields still render", () => {
    const old = item({ summary: undefined, trustSources: undefined, unattended: undefined });
    expect(formatQueue([old], { width: 80, now: NOW })).toContain("Push commits to origin");
  });
});

describe("formatShow", () => {
  it("prints a proposed edit as a diff against the file", () => {
    const it2 = item({ tool: "Edit", kind: "proposal", rules: ["FW-INSTRUCTIONS-HELD"], summary: "Change CLAUDE.md", proposal: { target: "/w/CLAUDE.md", change: "x", edits: [{ old: "# acme-shop", new: "# acme-shop\n\nNotes added." }] } });
    const out = formatShow(it2, { width: 80, now: NOW, currentContent: "# acme-shop\n" });
    expect(out).toContain("Proposed change to /w/CLAUDE.md:");
    expect(out).toContain("  # acme-shop");
    expect(out).toContain("+ Notes added.");
    expect(out).toContain("Nothing was written.");
  });
  it("prints a proposed new file content as added lines", () => {
    const it2 = item({ tool: "Write", kind: "proposal", proposal: { target: "/w/CLAUDE.md", change: "x", content: "one\ntwo" } });
    const out = formatShow(it2, { width: 80, now: NOW, currentContent: "one\n" });
    expect(out).toContain("  one");
    expect(out).toContain("+ two");
  });
  it("lineDiff keeps common lines and marks changes", () => {
    expect(lineDiff("a\nb\nc", "a\nx\nc")).toEqual(["  a", "- b", "+ x", "  c"]);
    expect(lineDiff("# t\n", "# t\n\nNotes.\n")).toEqual(["  # t", "+ ", "+ Notes."]);
  });
});

describe("formatStatus", () => {
  it("shows trust per session, since when and why, held count and unattended mode", () => {
    const out = formatStatus(
      {
        version: "0.1.0",
        stateDir: "/s",
        installedIn: ["project (/w/.claude/settings.json)"],
        sessions: [
          { id: "night-3am", lastActivity: new Date(2026, 9, 9, 3, 16), trusted: false, untrustedSince: new Date(2026, 9, 9, 3, 12), firstSource: "read from gmail.read_message", sensitive: false, unattended: "permission mode dontAsk" },
          { id: "morning", lastActivity: new Date(2026, 9, 9, 8, 50), trusted: true, untrustedSince: null, firstSource: null, sensitive: false, unattended: null },
        ],
        held: 2,
        unattended: { on: true, why: "inside unattended hours 22:00-07:00" },
        decisions: { allow: 3, ask: 0, queue: 2, deny: 1, total: 6 },
      },
      { width: 72, now: NOW },
    );
    expect(out).toContain("Unattended mode: on (inside unattended hours 22:00-07:00)");
    expect(out).toContain("Held for you: 2");
    expect(out).toMatch(/night-3am · last active 3:16 AM · UNTRUSTED/);
    expect(out.replace(/\s+/g, " ")).toContain("since 3:12 AM, after reading: an email from gmail.read_message");
    expect(out.replace(/\s+/g, " ")).toContain("ran unattended (permission mode dontAsk)");
    expect(out).toMatch(/morning · last active 8:50 AM · trusted/);
    fits(out, 72);
  });
});

describe("through the real hook and CLI", () => {
  let root: string, ws: string, l: ReturnType<typeof layout>;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "lsfw-rep-"));
    ws = join(root, "ws");
    mkdirSync(ws, { recursive: true });
    writeFileSync(join(ws, "CLAUDE.md"), "# acme-shop\n");
    l = layout(join(root, "fw"));
    const e = { env: { CLAUDE_PROJECT_DIR: ws }, layout: l, detectNonInteractive: () => true };
    const send = (ev: Record<string, unknown>): void => void runHook(JSON.stringify({ session_id: "night-3am", cwd: ws, permission_mode: "default", ...ev }), e);
    send({ hook_event_name: "PostToolUse", tool_name: "mcp__gmail__read_message", tool_input: { id: "m1" }, tool_response: "an email" });
    send({ hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: { file_path: join(ws, "CLAUDE.md"), old_string: "# acme-shop", new_string: "# acme-shop\n\nNotes added." } });
    send({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "git push origin main" } });
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));
  const cli = (args: string[], columns = "70"): string => spawnCli(args, { cwd: ws, env: { LAUNCHSAFE_FIREWALL_HOME: l.home, COLUMNS: columns } }).stdout;

  it("queue items carry the summary, the trust source and the unattended flag", () => {
    const items = listQueue(l).items;
    expect(items.map((i) => i.summary).sort()).toEqual(["Change CLAUDE.md", "Push commits to origin"]);
    expect(items.every((i) => i.trustSources?.some((s) => s.includes("gmail.read_message")))).toBe(true);
    expect(items.find((i) => i.kind === "proposal")?.proposal?.edits).toEqual([{ old: "# acme-shop", new: "# acme-shop\n\nNotes added." }]);
  });
  it("`queue` prints the morning summary wrapped to the terminal", () => {
    const out = cli(["queue"]);
    expect(out.split("\n")[0]).toBe("2 actions held while you were away");
    expect(out.replace(/\s+/g, " ")).toContain("after reading: an email from gmail.read_message");
    fits(out.trimEnd(), 70);
  });
  it("`queue --json` is the full machine format (the stored items)", () => {
    const parsed = JSON.parse(cli(["queue", "--json"])) as QueueItem[];
    expect(parsed).toEqual(listQueue(l).items.filter((i) => i.status === "pending"));
    expect(Object.keys(parsed[0] ?? {})).toEqual(expect.arrayContaining(["version", "id", "createdAt", "sessionId", "tool", "input", "actionHash", "rules", "reasons", "kind", "status"]));
  });
  it("`queue show` prints the proposed diff", () => {
    const id = listQueue(l).items.find((i) => i.kind === "proposal")?.id ?? "";
    const out = cli(["queue", "show", id]);
    expect(out).toContain("+ Notes added.");
    expect(out).toContain("  # acme-shop");
  });
  it("`status` shows the session became untrusted, when and why", () => {
    const out = cli(["status"], "80");
    expect(out).toMatch(/night-3am · last active .* · UNTRUSTED/);
    expect(out.replace(/\s+/g, " ")).toMatch(/since \d{1,2}:\d{2} [AP]M, after reading: an email from gmail\.read_message/);
    expect(out).toContain("Held for you: 2");
    expect(out).toMatch(/Unattended mode: (on|off)/);
    expect(recentSessions(l)[0]?.trusted).toBe(false);
    expect(recentSessions(l)[0]?.unattended).not.toBeNull();
  });
});

describe("R19: the proposal diff applies replace_all", () => {
  const base = { version: 1 as const, id: "q9", createdAt: "2026-10-10T08:00:00.000Z", sessionId: "s", cwd: "/w", tool: "Edit", actionHash: "h", rules: ["FW-INSTRUCTIONS-HELD"], reasons: ["r"], kind: "proposal" as const, status: "pending" as const };
  it("a stored all flag replaces every occurrence; without it only the first", () => {
    const withAll = formatShow({ ...base, input: {}, proposal: { target: "/w/CLAUDE.md", change: "x", edits: [{ old: "a", new: "b", all: true }] } }, { width: 100, currentContent: "a\nkeep\na\n" });
    expect(withAll.split("\n").filter((x) => x === "+ b")).toHaveLength(2);
    const first = formatShow({ ...base, input: {}, proposal: { target: "/w/CLAUDE.md", change: "x", edits: [{ old: "a", new: "b" }] } }, { width: 100, currentContent: "a\nkeep\na\n" });
    expect(first.split("\n").filter((x) => x === "+ b")).toHaveLength(1);
  });
  it("\"$&\" in the new text is shown literally", () => {
    const out = formatShow({ ...base, input: {}, proposal: { target: "/w/CLAUDE.md", change: "x", edits: [{ old: "a", new: "$&$&" }] } }, { width: 100, currentContent: "a\n" });
    expect(out).toContain("+ $&$&");
  });
});
