/**
 * Shared taint between the browser and linked agent sessions: only ever added, never cleared; a browser
 * taint reaches sessions linked now and sessions that link while it is recent; unreadable state is taint.
 */

import { appendFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { capLockWaits } from "../../src/runtime/fsutil.js";
import { layout, type Layout } from "../../src/runtime/layout.js";
import { isBrowserServer, LINK_WINDOW_MS, linkBrowserSession, linkedSessions, linkStateProblems, recordBrowserTaint, taintedLinkedSessions } from "../../src/runtime/native/link.js";
import { appendEvents, loadState } from "../../src/runtime/store.js";

let root: string;
let l: Layout;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "lsfw-link-"));
  l = layout(join(root, "home"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const T0 = new Date("2026-10-11T10:00:00Z");
const later = (ms: number): Date => new Date(T0.getTime() + ms);

describe("which MCP servers drive a browser", () => {
  it("matches the browser-driving servers by name, and nothing else", () => {
    for (const s of ["claude-in-chrome", "chrome-devtools", "browsermcp", "playwright", "Playwright", "playwright-extension"]) expect(isBrowserServer(s)).toBe(true);
    for (const s of ["github", "filesystem", "chrome", "my-playwright", "slack"]) expect(isBrowserServer(s)).toBe(false);
  });
});

describe("browser taint to agent sessions", () => {
  it("a session linked before the browser taint is tainted when the taint arrives", () => {
    expect(linkBrowserSession(l, "s1", T0)).toEqual([]);
    expect(recordBrowserTaint(l, "ext-1", "outside_origin", later(1000))).toBe(1);
    const st = loadState(l, "s1");
    expect(st.tainted).toBe(true);
    expect(st.taintSources).toEqual(["the linked browser session read outside content (outside_origin)"]);
  });

  it("a session that links while a browser taint is recent gets it on that call", () => {
    recordBrowserTaint(l, "ext-1", "quarantine_verdict", T0);
    expect(linkBrowserSession(l, "s2", later(60_000))).toEqual([{ type: "taint", source: "the linked browser session read outside content (quarantine_verdict)" }]);
  });

  it("an old browser taint and an old link no longer count after the window", () => {
    recordBrowserTaint(l, "ext-1", "outside_origin", T0);
    expect(linkBrowserSession(l, "s3", later(LINK_WINDOW_MS + 1))).toEqual([]);
    expect(linkedSessions(l, later(2 * LINK_WINDOW_MS + 2))).toEqual([]);
    expect(recordBrowserTaint(l, "ext-1", "outside_origin", later(2 * LINK_WINDOW_MS + 2))).toBe(0);
  });

  it("does not touch sessions that never drove the browser", () => {
    appendEvents(l, "other", [{ type: "fingerprint", hash: "x" }]);
    linkBrowserSession(l, "s1", T0);
    recordBrowserTaint(l, "ext-1", "outside_origin", T0);
    expect(loadState(l, "other").tainted).toBe(false);
  });

  it("a damaged taint record taints every session that links (fail closed), and doctor names it", () => {
    mkdirSync(join(l.home, "browser"), { recursive: true });
    writeFileSync(join(l.home, "browser", "taint.jsonl"), "{not json\n");
    expect(linkBrowserSession(l, "s1", T0)).toEqual([{ type: "taint", source: "the browser link's taint record could not be read" }]);
    expect(linkStateProblems(l).join(" ")).toMatch(/taint\.jsonl has unreadable lines/);
  });

  it("does not rewrite the link on every call", () => {
    linkBrowserSession(l, "s1", T0);
    linkBrowserSession(l, "s1", later(1000));
    linkBrowserSession(l, "s1", later(2000));
    appendFileSync(join(l.home, "browser", "links.jsonl"), "");
    expect(linkedSessions(l, later(3000))).toEqual(["s1"]);
  });
});

describe("agent taint to the browser", () => {
  it("reports linked sessions that are tainted, and only those", () => {
    linkBrowserSession(l, "clean", T0);
    linkBrowserSession(l, "dirty", T0);
    appendEvents(l, "dirty", [{ type: "taint", source: "read the web page https://example.test" }]);
    expect(taintedLinkedSessions(l, later(1000))).toEqual(["dirty"]);
  });
});

describe("appends take the compaction lock", () => {
  it("a taint or a link is not appended while another process holds the file's lock", () => {
    mkdirSync(join(l.home, "browser"), { recursive: true });
    const before = capLockWaits(50);
    try {
      for (const [file, run] of [
        ["taint.jsonl", () => recordBrowserTaint(l, "ext-1", "outside_origin", T0)],
        ["links.jsonl", () => linkBrowserSession(l, "s1", T0)],
      ] as const) {
        const lock = join(l.home, "browser", `${file}.lock`);
        // The parent process is alive and is not this one: a holder compact would be waiting on too.
        writeFileSync(lock, `${process.ppid} ${Date.now()}`);
        try {
          run();
        } catch {
          // recordBrowserTaint throws when the lock cannot be taken; linkBrowserSession reports it as taint.
        }
        expect(existsSync(join(l.home, "browser", file))).toBe(false);
        rmSync(lock, { force: true });
      }
    } finally {
      capLockWaits(before);
    }
  });
});
