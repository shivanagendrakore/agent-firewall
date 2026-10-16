/**
 * The API's commands through main() and its handlers, in a temporary firewall home: token add prints the
 * token once and stores only its hash; list never shows a token; revoke; tools set validates before it
 * writes; the person check refuses an agent's process; serve --api starts, logs and stops.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { API_HANDLERS, type ApiCliDeps } from "../../src/api-cli.js";
import { readRegistry } from "../../src/api/registry.js";
import { readTokens } from "../../src/api/tokens.js";
import { COMMANDS, parseCommandLine } from "../../src/cliargs.js";
import { main } from "../../src/climain.js";
import { tailLog } from "../../src/runtime/log.js";
import { apiTree, call, REGISTRY, removeApiTree, type ApiTree } from "./harness.js";

describe("api token and api tools", () => {
  let t: ApiTree;
  beforeEach(() => {
    t = apiTree();
  });
  afterEach(() => removeApiTree(t));

  async function cli(argv: string[], human = true): Promise<{ code: number; out: string; err: string }> {
    let out = "";
    let err = "";
    const code = await main(argv, t.l, { write: (fd, s) => void (fd === 1 ? (out += s) : (err += s)), humanAtKeyboard: async () => human });
    return { code, out, err };
  }

  it("token add prints the token once and keeps only its SHA-256; list shows no token; revoke removes it", async () => {
    const a = await cli(["api", "token", "add", "bot"]);
    expect(a.code, a.err).toBe(0);
    const token = /lsfw_[A-Za-z0-9_-]{43}/.exec(a.out)?.[0] as string;
    expect(token).toBeDefined();
    expect(readFileSync(join(t.l.home, "api", "tokens.json"), "utf8")).not.toContain(token);
    const list = await cli(["api", "token", "list", "--json"]);
    expect(list.code).toBe(0);
    expect(list.out).not.toContain(token);
    expect(JSON.parse(list.out)).toEqual([{ agent: "bot", createdAt: expect.any(String), id: expect.stringMatching(/^[0-9a-f]{12}$/), roles: ["decide", "report"] }]);
    expect((await cli(["api", "token", "list"])).out).toMatch(/^bot {2}token [0-9a-f]{12}…/);
    expect((await cli(["api", "token", "revoke", "bot"])).code).toBe(0);
    expect(readTokens(t.l)).toEqual([]);
    expect((await cli(["api", "token", "revoke", "bot"])).code).toBe(1);
    expect(tailLog(t.l, 10).map((e) => e.event)).toEqual(expect.arrayContaining([{ type: "api", event: "token_added", agent: "bot" }, { type: "api", event: "token_revoked", agent: "bot", count: 1 }]));
    expect(JSON.stringify(tailLog(t.l, 10))).not.toContain(token);
  });

  it("tools set validates the file before anything is written; show prints it", async () => {
    const good = join(t.root, "tools.json");
    writeFileSync(good, JSON.stringify(REGISTRY));
    const set = await cli(["api", "tools", "set", "bot", good]);
    expect(set.code, set.err).toBe(0);
    expect(set.out).toMatch(/7 tools/);
    const show = await cli(["api", "tools", "show", "bot"]);
    expect(JSON.parse(show.out)).toEqual(REGISTRY);
    const bad = join(t.root, "bad.json");
    writeFileSync(bad, JSON.stringify({ tools: { run: { as: "Bash", map: { command: "$.args[0]" } } } }));
    const r = await cli(["api", "tools", "set", "bot", bad]);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/dot path.*Nothing was changed/);
    expect(readRegistry(t.l, "bot")).toEqual(REGISTRY);
    writeFileSync(bad, "{ not json");
    expect((await cli(["api", "tools", "set", "bot", bad])).code).toBe(1);
    expect((await cli(["api", "tools", "show", "nobody"])).code).toBe(1);
  });

  it("refused when an agent started the process, before anything changes", async () => {
    for (const argv of [["api", "token", "add", "bot"], ["api", "token", "list"], ["api", "token", "revoke", "bot"], ["api", "tools", "show", "bot"], ["serve", "--api"]]) {
      const r = await cli(argv, false);
      expect(r.code, argv.join(" ")).toBe(1);
      expect(r.err).toMatch(/from inside an agent session/);
    }
    expect(readTokens(t.l)).toEqual([]);
  });

  it("bad agent ids and serve without --api are usage errors; --listen off loopback is refused", async () => {
    expect((await cli(["api", "token", "add", "../x"])).code).toBe(64);
    expect((await cli(["serve"])).code).toBe(64);
    const r = await cli(["serve", "--api", "--listen", "0.0.0.0:8787"]);
    expect(r.code).toBe(64);
    expect(r.err).toMatch(/refused/);
  });

  it("every API command is declared state-changing (so the engine refuses it to agents)", () => {
    const api = COMMANDS.filter((c) => c.path[0] === "serve" || c.path[0] === "api");
    expect(api.map((c) => c.path.join(" ")).sort()).toEqual(["api token add", "api token list", "api token revoke", "api tools set", "api tools show", "serve"]);
    expect(api.every((c) => c.changesState)).toBe(true);
    expect(parseCommandLine(["serve", "--api", "--listen", "127.0.0.1:1"]).kind).toBe("ok");
  });

  it("serve --api: listens on the socket, logs start and stop, and removes the socket when stopped", async () => {
    let out = "";
    let stopIt: () => void = () => undefined;
    let address = "";
    const up = new Promise<void>((r) => {
      const deps: ApiCliDeps = {
        out: (s) => void (out += `${s}\n`),
        err: () => undefined,
        notAgent: async () => true,
        cwd: t.root,
        env: {},
        onListening: (stop, a) => {
          stopIt = stop;
          address = a;
          r();
        },
      };
      void (API_HANDLERS.serve as NonNullable<(typeof API_HANDLERS)["serve"]>)(parseCommandLine(["serve", "--api"]) as never, t.l, deps).then((code) => {
        out += `exit ${code}\n`;
      });
    });
    await up;
    expect(address).toBe(`unix:${join(t.l.home, "api.sock")}`);
    expect(out).toMatch(/No agent has a token yet/);
    const health = await call({ socket: join(t.l.home, "api.sock") } as never, { path: "/v1/health" });
    expect(health.status).toBe(200);
    stopIt();
    await new Promise((r) => setTimeout(r, 50));
    expect(out).toMatch(/exit 0/);
    expect(tailLog(t.l, 5).map((e) => (e.event as { event?: string }).event)).toEqual(["server_started", "server_stopped"]);
  });
});
