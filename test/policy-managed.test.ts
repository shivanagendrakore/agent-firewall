/**
 * FM1: the administrator's managed policy holds under the user's. A user's mcpServers entry (exact or
 * pattern) the managed file covers starts from the managed entry and merges tighten-only; a user entry for
 * a server the managed file does not cover keeps today's behaviour. A user's userOutputTools entry cannot
 * take a managed server's tool out of the MCP checks.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig, mergeManaged, mergeTrusted, validatePolicy } from "../src/policy.js";
import { loadPolicy } from "../src/runtime/config.js";
import { layout, PROJECT_POLICY_FILE } from "../src/runtime/layout.js";
import { serverPolicy, toolKind } from "../src/engine/mcp.js";
import { hostTool } from "../src/engine/hosttools.js";
import type { FirewallConfig, McpServerPolicy } from "../src/types.js";
import { tempHome } from "./helpers.js";

type Raw = Record<string, unknown>;
type Servers = Record<string, McpServerPolicy>;

const doc = (servers: Servers, extra: Raw = {}, version = 3): Raw => ({ version, mcpServers: servers, ...extra });
/** The user's file, then the administrator's, as loadPolicy merges them. */
function layered(user: Raw, managed: Raw): { config: FirewallConfig; notes: string[] } {
  return mergeManaged(mergeTrusted(defaultConfig(), validatePolicy(user, "user")), validatePolicy(managed, "managed"));
}
const cfg = (user: Servers, managed: Servers, userExtra: Raw = {}, managedExtra: Raw = {}): FirewallConfig => layered(doc(user, userExtra), doc(managed, managedExtra)).config;

const TRUSTED: McpServerPolicy = { results: "trusted", privateData: false };
const UNTRUSTED: McpServerPolicy = { results: "untrusted", privateData: true };

describe("FM1: a managed pattern holds under a user's exact entry, field by field", () => {
  it("results: the administrator's untrusted wins over the user's trusted", () => {
    const c = cfg({ "corp-wiki": TRUSTED }, { "corp-*": { results: "untrusted", privateData: false } });
    expect(serverPolicy("corp-wiki", c).results).toBe("untrusted");
  });

  it("privateData: the administrator's true wins over the user's false", () => {
    const c = cfg({ "corp-wiki": TRUSTED }, { "corp-*": { results: "trusted", privateData: true } });
    expect(serverPolicy("corp-wiki", c)).toMatchObject({ results: "trusted", privateData: true });
  });

  it("blockedTools: a union, so the administrator's blocked tool stays blocked", () => {
    const c = cfg({ "corp-wiki": { ...TRUSTED, blockedTools: ["wipe"] } }, { "corp-*": { ...TRUSTED, blockedTools: ["send_all"] } });
    const p = serverPolicy("corp-wiki", c);
    expect(p.blockedTools).toEqual(expect.arrayContaining(["send_all", "wipe"]));
    expect(toolKind("send_all", p)).toBe("blocked");
  });

  it("sendTools: a union, and the user's readTools cannot reclassify an administrator's send tool", () => {
    const c = cfg({ "corp-wiki": { ...TRUSTED, readTools: ["export_*"], sendTools: ["share"] } }, { "corp-*": { ...TRUSTED, sendTools: ["export_*"] } });
    const p = serverPolicy("corp-wiki", c);
    expect(p.sendTools).toEqual(expect.arrayContaining(["export_*", "share"]));
    expect(p.readTools).toBeUndefined();
    expect(toolKind("export_all", p)).toBe("send");
  });

  it("destructiveTools: a union", () => {
    const c = cfg({ "corp-wiki": { ...TRUSTED, destructiveTools: ["drop"] } }, { "corp-*": { ...TRUSTED, destructiveTools: ["purge_*"] } });
    expect(serverPolicy("corp-wiki", c).destructiveTools).toEqual(expect.arrayContaining(["purge_*", "drop"]));
  });

  it("readTools: the administrator's are kept, the user's are not added", () => {
    const c = cfg({ "corp-wiki": { ...TRUSTED, readTools: ["post_*"] } }, { "corp-*": { ...TRUSTED, readTools: ["list_*"] } });
    expect(serverPolicy("corp-wiki", c).readTools).toEqual(["list_*"]);
  });

  it("the user's restrictions still apply on top (untrusted, private, extra blocked tools)", () => {
    const c = cfg({ "corp-wiki": { ...UNTRUSTED, blockedTools: ["wipe"] } }, { "corp-*": TRUSTED });
    expect(serverPolicy("corp-wiki", c)).toMatchObject({ results: "untrusted", privateData: true, blockedTools: ["wipe"] });
  });

  it("the managed exact name is used over its pattern, as serverPolicy would", () => {
    const c = cfg({ "corp-wiki": TRUSTED }, { "corp-wiki": { ...TRUSTED, blockedTools: ["a"] }, "corp-*": { ...UNTRUSTED, blockedTools: ["b"] } });
    expect(serverPolicy("corp-wiki", c)).toMatchObject({ results: "trusted", blockedTools: ["a"] });
  });

  it("other servers under the managed pattern get the managed entry", () => {
    const c = cfg({ "corp-wiki": { ...TRUSTED, blockedTools: ["wipe"] } }, { "corp-*": { ...UNTRUSTED, blockedTools: ["send_all"] } });
    expect(serverPolicy("corp-chat", c)).toMatchObject({ results: "untrusted", blockedTools: ["send_all"] });
  });

  it("notes the loosening that did not apply, and only that", () => {
    const r = layered(doc({ "corp-wiki": TRUSTED, other: TRUSTED }), doc({ "corp-*": UNTRUSTED }));
    expect(r.notes).toEqual(["mcpServers.corp-wiki: the managed policy covers this server; the user policy's loosening (trusted results, privateData false or readTools) is not applied"]);
    expect(layered(doc({ "corp-wiki": UNTRUSTED }), doc({ "corp-*": UNTRUSTED })).notes).toEqual([]);
  });
});

describe("FM1: user patterns over managed entries", () => {
  it("a user catch-all pattern no longer hides a managed pattern", () => {
    const c = cfg({ "*": TRUSTED }, { "corp-*": { ...UNTRUSTED, blockedTools: ["send_all"] } });
    expect(serverPolicy("corp-wiki", c)).toMatchObject({ results: "untrusted", privateData: true, blockedTools: ["send_all"] });
  });

  it("a broad user pattern keeps its settings for servers the narrower managed pattern does not cover", () => {
    const c = cfg({ "corp-*": { ...TRUSTED, blockedTools: ["wipe"] } }, { "corp-wiki*": { ...UNTRUSTED, blockedTools: ["send_all"] } });
    expect(serverPolicy("corp-wiki-eu", c)).toMatchObject({ results: "untrusted", privateData: true });
    expect(serverPolicy("corp-wiki-eu", c).blockedTools).toEqual(expect.arrayContaining(["send_all", "wipe"]));
    expect(serverPolicy("corp-chat", c)).toEqual({ ...TRUSTED, blockedTools: ["wipe"] });
  });

  it("a narrow user pattern under a broad managed pattern is tightened", () => {
    const c = cfg({ "corp-wiki*": TRUSTED }, { "corp-*": { ...UNTRUSTED, sendTools: ["export"] } });
    expect(serverPolicy("corp-wiki-eu", c)).toMatchObject({ results: "untrusted", sendTools: ["export"] });
  });

  it("the same pattern in both files merges tighten-only", () => {
    const c = cfg({ "corp-*": { ...TRUSTED, blockedTools: ["a"] } }, { "corp-*": { ...UNTRUSTED, blockedTools: ["b"] } });
    expect(serverPolicy("corp-x", c)).toMatchObject({ results: "untrusted", blockedTools: expect.arrayContaining(["a", "b"]) as unknown as string[] });
  });

  it("a user pattern that does not overlap a managed pattern is unchanged", () => {
    const c = cfg({ "docs-*": { ...TRUSTED, readTools: ["search"] } }, { "corp-*": UNTRUSTED });
    expect(serverPolicy("docs-a", c)).toEqual({ ...TRUSTED, readTools: ["search"] });
  });

  it("a managed prefix pattern inside a user catch-all is exact: other managed prefixes do not leak into it", () => {
    const c = cfg({ "*": TRUSTED }, { "corp-*": { ...TRUSTED, readTools: ["post_*"] }, "mail-*": { ...TRUSTED, readTools: ["list_*"] } });
    expect(serverPolicy("corp-wiki", c).readTools).toEqual(["post_*"]);
    expect(serverPolicy("mail-corp", c).readTools).toEqual(["list_*"]);
    expect(serverPolicy("other", c)).toEqual(TRUSTED);
  });

  it("managed readTools that disagree across possibly overlapping managed patterns are dropped (verb-based classification)", () => {
    const c = cfg({ "*": TRUSTED }, { "corp-*": { ...TRUSTED, readTools: ["post_*"] }, "*-mail": { ...TRUSTED, readTools: ["list_*"] } });
    expect(serverPolicy("corp-wiki", c).readTools).toBeUndefined();
    expect(toolKind("post_message", serverPolicy("corp-wiki", c))).toBe("send");
    // The catch-all is tightened by "*-mail" (it may match the same servers) but never loosened by its readTools.
    expect(serverPolicy("other", c)).toEqual(TRUSTED);
  });

  it("a managed pattern that may only partly overlap a user pattern adds restrictions, never its readTools", () => {
    const c = cfg({ "corp-*": TRUSTED }, { "*-mail": { ...UNTRUSTED, readTools: ["send_*"], blockedTools: ["wipe"] } });
    const p = serverPolicy("corp-chat", c);
    expect(p).toMatchObject({ results: "untrusted", privateData: true, blockedTools: ["wipe"] });
    expect(p.readTools).toBeUndefined();
  });
});

describe("FM1: a managed exact entry under a user pattern", () => {
  it("the managed exact entry holds, and the user's pattern only adds restrictions", () => {
    const c = cfg({ "corp-*": { ...TRUSTED, blockedTools: ["wipe"] } }, { "corp-wiki": { ...UNTRUSTED, blockedTools: ["send_all"] } });
    const p = serverPolicy("corp-wiki", c);
    expect(p).toMatchObject({ results: "untrusted", privateData: true });
    expect(p.blockedTools).toEqual(expect.arrayContaining(["send_all", "wipe"]));
    expect(serverPolicy("corp-chat", c)).toEqual({ ...TRUSTED, blockedTools: ["wipe"] });
  });

  it("a trusted managed exact entry stays trusted under a user pattern that does not restrict", () => {
    const c = cfg({ "corp-*": TRUSTED }, { "corp-wiki": TRUSTED });
    expect(serverPolicy("corp-wiki", c)).toEqual(TRUSTED);
  });
});

describe("FM1: no managed entry for the server, unchanged", () => {
  const user: Servers = { "corp-wiki": { ...TRUSTED, readTools: ["post"] }, "docs-*": TRUSTED, "*": { ...UNTRUSTED, blockedTools: ["x"] } };
  it("no managed file entries at all: the merged map is exactly mergeTrusted's", () => {
    const before = mergeTrusted(mergeTrusted(defaultConfig(), validatePolicy(doc(user), "u")), validatePolicy({ version: 3, denyHosts: ["a.example"] }, "m"));
    const after = layered(doc(user), { version: 3, denyHosts: ["a.example"] });
    expect(after.config).toEqual(before);
    expect(Object.keys(after.config.mcpServers)).toEqual(Object.keys(user));
    expect(after.notes).toEqual([]);
  });

  it("a managed entry for other servers leaves the user's entries for theirs as they were", () => {
    const c = cfg({ "corp-wiki": { ...TRUSTED, readTools: ["post"] }, "docs-*": TRUSTED }, { "vault-*": UNTRUSTED });
    expect(serverPolicy("corp-wiki", c)).toEqual({ ...TRUSTED, readTools: ["post"] });
    expect(serverPolicy("docs-a", c)).toEqual(TRUSTED);
    expect(serverPolicy("vault-x", c)).toEqual(UNTRUSTED);
  });
});

describe("FM1: userOutputTools cannot take a managed server's tool out of the MCP checks", () => {
  it("a user entry for a managed server's tool is dropped and noted; others are kept", () => {
    const r = layered(doc({}, { userOutputTools: ["mcp__corp-wiki__send_all", "mcp__other__show", "ShowThing"] }), doc({ "corp-*": { ...TRUSTED, blockedTools: ["send_all"] } }));
    expect(r.config.userOutputTools).toEqual(["mcp__other__show", "ShowThing"]);
    expect(hostTool("mcp__corp-wiki__send_all", undefined, r.config)).toBeNull();
    expect(r.notes).toEqual(["userOutputTools.mcp__corp-wiki__send_all: the managed policy has an entry for corp-wiki, so the user policy cannot mark its tools as only showing things to you"]);
  });

  it("the administrator's own userOutputTools is kept as written", () => {
    const r = layered(doc({}, { userOutputTools: ["mcp__corp-wiki__a"] }), doc({ "corp-*": UNTRUSTED }, { userOutputTools: ["mcp__corp-wiki__show"] }));
    expect(r.config.userOutputTools).toEqual(["mcp__corp-wiki__show"]);
  });
});

describe("FM1: through loadPolicy, with version 2 and version 3 files mixed", () => {
  const MANAGED: Raw = { mcpServers: { "corp-*": { results: "untrusted", privateData: true, blockedTools: ["send_all"] } } };
  const USER: Raw = { mcpServers: { "corp-wiki": { results: "trusted", privateData: false, readTools: ["send_all"] }, "docs-*": { results: "trusted", privateData: false } }, userOutputTools: ["mcp__corp-wiki__send_all"] };
  const PROJECT: Raw = { mcpServers: { "corp-wiki": { results: "untrusted", privateData: true, blockedTools: ["wipe"] } } };
  const combos: [number, number, number][] = [2, 3].flatMap((u) => [2, 3].flatMap((m) => [2, 3].map((p): [number, number, number] => [u, m, p])));

  it.each(combos)("user v%i, managed v%i, project v%i: the administrator's pattern holds under the user's exact entry", (uv, mv, pv) => {
    const home = tempHome("fm1-");
    const l = layout(join(home, ".launchsafe-firewall"));
    mkdirSync(l.home, { recursive: true });
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    const managed = join(home, "managed.json");
    writeFileSync(l.policy, JSON.stringify({ ...USER, version: uv }));
    writeFileSync(managed, JSON.stringify({ ...MANAGED, version: mv }));
    writeFileSync(join(ws, PROJECT_POLICY_FILE), JSON.stringify({ ...PROJECT, version: pv }));
    const p = loadPolicy(l, [ws], "darwin", managed);
    expect(p.error).toBeUndefined();
    const mail = serverPolicy("corp-wiki", p.config);
    expect(mail).toMatchObject({ results: "untrusted", privateData: true });
    expect(mail.blockedTools).toEqual(expect.arrayContaining(["send_all", "wipe"]));
    expect(toolKind("send_all", mail)).toBe("blocked");
    expect(serverPolicy("docs-a", p.config)).toEqual(TRUSTED);
    expect(p.config.userOutputTools).toEqual([]);
    expect(p.notes.filter((n) => n.includes("mcpServers.corp-wiki") || n.includes("userOutputTools."))).toHaveLength(2);
  });
});
