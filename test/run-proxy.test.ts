/**
 * v0.3 `run`: the allowlist proxy, outside any sandbox (every platform). Upstream connections go to
 * servers on 127.0.0.1 through the test-only dial; the real dial's DNS-rebinding refusal is checked
 * with "localhost", which resolves locally. The Linux bridge is run here too, without bubblewrap.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttpServer, request, type Server as HttpServer } from "node:http";
import { connect, createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RunBudgets, runNetPolicy } from "../src/engine/netgate.js";
import { buildClientHello } from "../src/engine/tls-sni.js";
import { defaultConfig } from "../src/policy.js";
import { BRIDGE_MARKER } from "../src/engine/run-profile.js";
import { BRIDGE_SOURCE } from "../src/runtime/run/bridge.js";
import { checkedDial, DialRefused, MAX_STAT_HOSTS, OTHER_HOSTS, parseAuthority, startProxy, type ProxyEvent, type RunningProxy } from "../src/runtime/run/proxy.js";
import type { FirewallConfig } from "../src/types.js";

let web: HttpServer;
let webPort = 0;
let echo: Server;
let echoPort = 0;
let echoed = 0;

beforeAll(async () => {
  web = createHttpServer((q, r) => {
    let body = "";
    q.on("data", (c: Buffer) => (body += c.toString()));
    q.on("end", () => r.end(`web ${q.method} ${q.headers.host} ${q.url} ${body.length}`));
  });
  await new Promise<void>((r) => web.listen(0, "127.0.0.1", () => r()));
  webPort = (web.address() as { port: number }).port;
  echo = createServer((s) => {
    s.on("data", (c: Buffer) => {
      echoed += c.length;
      s.write(c);
    });
    s.on("error", () => undefined);
  });
  await new Promise<void>((r) => echo.listen(0, "127.0.0.1", () => r()));
  echoPort = (echo.address() as { port: number }).port;
});
afterAll(() => {
  web.close();
  echo.close();
});

const toLocal = (port: () => number) => (_h: string, _p: number): Promise<Socket> =>
  new Promise((res, rej) => {
    const s = connect(port(), "127.0.0.1", () => res(s));
    s.on("error", rej);
  });

async function proxy(over: Partial<FirewallConfig> = {}, o: { sendHosts?: string[]; port?: () => number } = {}): Promise<{ p: RunningProxy; events: ProxyEvent[] }> {
  const { policy } = runNetPolicy({ ...defaultConfig(), fetchAllowHosts: ["allowed.test", "registry.npmjs.org"], denyHosts: ["denied.test"], ...over }, { sendHosts: o.sendHosts ?? [] });
  const events: ProxyEvent[] = [];
  const p = await startProxy({ policy, budgets: new RunBudgets(policy), listen: { host: "127.0.0.1" }, onEvent: (e) => events.push(e), dial: toLocal(o.port ?? (() => webPort)), helloTimeoutMs: 500 });
  return { p, events };
}

function get(p: RunningProxy, url: string, body?: string): Promise<{ status: number; body: string; headers: Record<string, unknown> }> {
  return new Promise((res, rej) => {
    const q = request({ host: "127.0.0.1", port: p.port as number, method: body === undefined ? "GET" : "POST", path: url, headers: { host: new URL(url).host } }, (r) => {
      let b = "";
      r.on("data", (c: Buffer) => (b += c.toString()));
      r.on("end", () => res({ status: r.statusCode ?? 0, body: b, headers: r.headers }));
    });
    q.on("error", rej);
    q.end(body);
  });
}

/** Opens a CONNECT tunnel; resolves with the status line and the socket. */
function tunnel(p: RunningProxy, target: string): Promise<{ status: string; s: Socket; rest: string }> {
  return new Promise((res, rej) => {
    const s = connect(p.port as number, "127.0.0.1", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let buf = "";
    const onData = (c: Buffer): void => {
      buf += c.toString("latin1");
      const end = buf.indexOf("\r\n\r\n");
      if (end === -1) return;
      s.removeListener("data", onData);
      res({ status: buf.split("\r\n")[0] as string, s, rest: buf.slice(end + 4) });
    };
    s.on("data", onData);
    s.on("error", rej);
  });
}

const closed = (s: Socket): Promise<void> => new Promise((r) => (s.destroyed ? r() : s.once("close", () => r())));

describe("plain HTTP (absolute form)", () => {
  it("forwards to an admitted host and counts the bytes", async () => {
    const { p, events } = await proxy();
    const r = await get(p, "http://allowed.test/x?y=1");
    expect(r.status).toBe(200);
    expect(r.body).toBe("web GET allowed.test /x?y=1 0");
    expect(events).toContainEqual(expect.objectContaining({ type: "net", verdict: "allow", host: "allowed.test", method: "HTTP" }));
    expect(p.stats()[0]).toMatchObject({ host: "allowed.test", conns: 1 });
    expect((p.stats()[0] as { up: number }).up).toBeGreaterThan(20);
    await p.close();
  });
  it("refuses a host that is not listed, a denied one, an IP and loopback, with 403 and the reason", async () => {
    const { p, events } = await proxy();
    for (const [url, why] of [["http://other.test/", "not-listed"], ["http://denied.test/", "denied-host"], ["http://10.0.0.1/", "raw-ip"], ["http://127.0.0.1:80/", "loopback"], ["http://169.254.169.254/latest/meta-data/", "metadata"], ["http://allowed.test:8080/", "port"]] as const) {
      const r = await get(p, url);
      expect(r.status, url).toBe(403);
      expect(r.headers["x-launchsafe-firewall"]).toBe("refused");
      expect(r.body).toContain("LaunchSafe Agent Firewall (run) refused");
      expect(events.some((e) => e.type === "net" && e.verdict === "deny" && e.why === why), `${url} ${why}`).toBe(true);
    }
    await p.close();
  });
  it("refuses origin-form requests and https:// URLs (those go through CONNECT)", async () => {
    const { p } = await proxy();
    expect((await get(p, "https://allowed.test/")).status).toBe(400);
    const origin = await new Promise<number>((res, rej) => {
      const q = request({ host: "127.0.0.1", port: p.port as number, path: "/x" }, (r) => {
        r.resume();
        res(r.statusCode ?? 0);
      });
      q.on("error", rej);
      q.end();
    });
    expect(origin).toBe(400);
    await p.close();
  });
  it("a request body past the per-host budget is cut off and logged", async () => {
    const { p, events } = await proxy({ budgets: { ...defaultConfig().budgets, untrusted: { ...defaultConfig().budgets.untrusted, bytesPerHost: 1000 } } });
    await get(p, "http://allowed.test/", "x".repeat(5000)).catch(() => ({ status: 0 }));
    expect(events).toContainEqual(expect.objectContaining({ type: "budget", host: "allowed.test" }));
    const again = await get(p, "http://allowed.test/");
    expect(again.status).toBe(403);
    expect(again.body).toContain("budgets");
    await p.close();
  });
});

describe("CONNECT tunnels", () => {
  it("opens a tunnel when the ClientHello names the CONNECT host, and relays both ways", async () => {
    const { p, events } = await proxy({}, { port: () => echoPort });
    const t = await tunnel(p, "allowed.test:443");
    expect(t.status).toBe("HTTP/1.1 200 Connection Established");
    const hello = buildClientHello("allowed.test");
    const back = await new Promise<number>((r) => {
      let n = 0;
      t.s.on("data", (c: Buffer) => {
        n += c.length;
        if (n >= hello.length + 5) r(n);
      });
      t.s.write(hello);
      setTimeout(() => t.s.write("more!"), 50);
    });
    expect(back).toBe(hello.length + 5);
    expect(events.filter((e) => e.type === "net" && e.verdict === "deny")).toEqual([]);
    t.s.destroy();
    await p.close();
  });
  it("closes the tunnel when TLS names another server (SNI mismatch), or none", async () => {
    for (const sni of ["evil.example", null]) {
      const { p, events } = await proxy({}, { port: () => echoPort });
      const before = echoed;
      const t = await tunnel(p, "allowed.test:443");
      t.s.write(buildClientHello(sni));
      await closed(t.s);
      expect(echoed, "nothing reached the server").toBe(before);
      expect(events).toContainEqual(expect.objectContaining({ verdict: "deny", why: "sni-mismatch", host: "allowed.test" }));
      await p.close();
    }
  });
  it("closes a 443 tunnel that does not carry TLS, or sends nothing in time", async () => {
    const { p, events } = await proxy({}, { port: () => echoPort });
    const t = await tunnel(p, "allowed.test:443");
    t.s.write("GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n");
    await closed(t.s);
    const t2 = await tunnel(p, "allowed.test:443");
    await closed(t2.s);
    expect(events.filter((e) => e.type === "net" && e.why === "not-tls").length).toBe(2);
    await p.close();
  });
  it("port 80 through CONNECT may carry plain HTTP (read and checked request by request)", async () => {
    const { p } = await proxy();
    const t = await tunnel(p, "allowed.test:80");
    const got = await new Promise<string>((r) => {
      let b = "";
      t.s.on("data", (c: Buffer) => {
        b += c.toString();
        if (b.includes("web GET")) r(b);
      });
      t.s.write("GET /x HTTP/1.1\r\nHost: allowed.test\r\n\r\n");
    });
    expect(got).toContain("web GET allowed.test /x 0");
    t.s.destroy();
    await p.close();
  });
  it("V19: inside a port-80 tunnel a Host naming another server is refused, the admitted host is what the upstream sees, and another server in the request line is refused", async () => {
    const { p, events } = await proxy();
    const talk = async (req: string): Promise<string> => {
      const t = await tunnel(p, "allowed.test:80");
      const got = await new Promise<string>((r) => {
        let b = "";
        t.s.on("data", (c: Buffer) => {
          b += c.toString();
          if (b.includes("\r\n\r\n") && /web |refused/.test(b)) r(b);
        });
        t.s.write(req);
      });
      t.s.destroy();
      return got;
    };
    expect(await talk("GET /x HTTP/1.1\r\nHost: other.example\r\n\r\n")).toMatch(/^HTTP\/1.1 403/);
    expect(await talk("GET http://other.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")).toMatch(/^HTTP\/1.1 403/);
    expect(await talk("GET /x HTTP/1.1\r\nHost: allowed.test:8080\r\n\r\n")).toMatch(/^HTTP\/1.1 403/);
    expect(await talk("GET /x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")).toContain("web GET allowed.test /x 0");
    expect(events.filter((e) => e.type === "net" && e.verdict === "deny" && e.why === "bad-host").length).toBe(3);
    await p.close();
  });
  it("RN9: a WebSocket upgrade inside a port-80 tunnel is admitted like a request (tunnel target, list, Host header), then relayed both ways with the admitted host", async () => {
    const seen: string[] = [];
    const wsServer = createHttpServer((_q, r) => r.end("plain"));
    wsServer.on("upgrade", (q, sock: Socket) => {
      seen.push(String(q.headers.host));
      sock.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
      sock.on("data", (c: Buffer) => sock.write(Buffer.concat([Buffer.from("echo:"), c])));
    });
    await new Promise<void>((r) => wsServer.listen(0, "127.0.0.1", () => r()));
    const wsPort = (wsServer.address() as { port: number }).port;
    const { p, events } = await proxy({}, { port: () => wsPort });
    const up = (host: string, path = "/ws"): string => `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`;
    const talk = async (req: string, then?: string): Promise<string> => {
      const t = await tunnel(p, "allowed.test:80");
      const got = await new Promise<string>((r) => {
        let b = "";
        let sent = false;
        t.s.on("data", (c: Buffer) => {
          b += c.toString("latin1");
          if (!b.includes("\r\n\r\n")) return;
          if (then !== undefined && b.startsWith("HTTP/1.1 101") && !sent) {
            sent = true;
            t.s.write(then);
          } else if (then === undefined || b.includes("echo:")) r(b);
        });
        t.s.on("close", () => r(b));
        t.s.write(req);
      });
      t.s.destroy();
      return got;
    };
    const ok = await talk(up("allowed.test"), "ping");
    expect(ok).toMatch(/^HTTP\/1.1 101/);
    expect(ok).toContain("echo:ping");
    expect(seen).toEqual(["allowed.test"]);
    expect(await talk(up("other.example"))).toMatch(/^HTTP\/1.1 403/);
    expect(await talk(up("allowed.test", "http://other.test/ws"))).toMatch(/^HTTP\/1.1 403/);
    expect(seen).toEqual(["allowed.test"]);
    expect(events.filter((e) => e.type === "net" && e.verdict === "deny" && e.why === "bad-host").length).toBe(2);
    // Absolute form outside a tunnel: an unlisted host is refused before dialing.
    const raw = connect(p.port as number, "127.0.0.1");
    const refused = await new Promise<string>((r) => {
      let b = "";
      raw.on("data", (c: Buffer) => (b += c.toString()));
      raw.on("close", () => r(b));
      raw.write(up("other.test", "http://other.test/ws"));
    });
    expect(refused).toMatch(/^HTTP\/1.1 403/);
    await p.close();
    wsServer.close();
  });
  it("an upgrade request with a second request pipelined behind it: the second is never relayed unless the server answers 101", async () => {
    const received: string[] = [];
    let answer = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno";
    const raw = createServer((sock) => {
      sock.on("data", (c: Buffer) => {
        received.push(c.toString("latin1"));
        if (received.join("").includes("\r\n\r\n") && !sock.writableEnded) sock.write(answer);
      });
      sock.on("error", () => undefined);
    });
    await new Promise<void>((r) => raw.listen(0, "127.0.0.1", () => r()));
    const rawPort = (raw.address() as { port: number }).port;
    const { p } = await proxy({}, { port: () => rawPort });
    const first = "GET http://allowed.test/ws HTTP/1.1\r\nHost: allowed.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    const second = "GET http://allowed.test/x HTTP/1.1\r\nHost: other.example\r\n\r\n";
    const talk = (): Promise<string> =>
      new Promise((r) => {
        const c = connect(p.port as number, "127.0.0.1");
        let b = "";
        c.on("data", (d: Buffer) => (b += d.toString("latin1")));
        c.on("close", () => r(b));
        c.on("error", () => r(b));
        c.write(first + second);
        setTimeout(() => c.destroy(), 400);
      });
    // Not 101: the answer is passed on, and the pipelined request never reaches the server.
    expect(await talk()).toMatch(/^HTTP\/1.1 200/);
    expect(received.join("")).not.toContain("other.example");
    // 101: the connection is not HTTP any more, so what the client queued is relayed after the answer.
    received.length = 0;
    answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    expect(await talk()).toMatch(/^HTTP\/1.1 101/);
    expect(received.join("")).toContain("other.example");
    await p.close();
    raw.close();
  });
  it("statistics: hosts past the cap are counted together under *other*", async () => {
    const { p } = await proxy();
    const port = p.port as number;
    for (let i = 0; i < MAX_STAT_HOSTS + 20; i++) {
      const s = connect(port, "127.0.0.1");
      await new Promise<void>((r) => {
        s.on("data", () => undefined);
        s.on("close", () => r());
        s.on("error", () => r());
        s.write(`CONNECT n${i}.unlisted.test:443 HTTP/1.1\r\nHost: n${i}.unlisted.test:443\r\n\r\n`);
      });
    }
    const st = p.stats();
    expect(st.length).toBeLessThanOrEqual(MAX_STAT_HOSTS + 1);
    expect(st.find((x) => x.host === OTHER_HOSTS)?.refused).toBe(20);
    await p.close();
  });
  it("V19: absolute-form: a Host naming another server is refused, and the upstream sees the admitted host", async () => {
    const { p } = await proxy();
    const send = (headers: Record<string, string>): Promise<{ status: number; body: string }> =>
      new Promise((res, rej) => {
        const q = request({ host: "127.0.0.1", port: p.port as number, method: "GET", path: "http://allowed.test/x", headers, setHost: false }, (r) => {
          let b = "";
          r.on("data", (c: Buffer) => (b += c.toString()));
          r.on("end", () => res({ status: r.statusCode ?? 0, body: b }));
        });
        q.on("error", rej);
        q.end();
      });
    expect((await send({ host: "other.example" })).status).toBe(403);
    expect((await send({ host: "allowed.test:81" })).status).toBe(403);
    expect(await send({ host: "ALLOWED.test:80" })).toMatchObject({ status: 200, body: "web GET allowed.test /x 0" });
    expect((await send({})).status).toBe(400); // HTTP/1.1 without Host is malformed (Node's parser says 400)
    await p.close();
  });
  it("refuses an unlisted CONNECT target with 403 before dialing", async () => {
    const { p, events } = await proxy({}, { port: () => echoPort });
    const t = await tunnel(p, "attacker.example:443");
    expect(t.status).toBe("HTTP/1.1 403 Forbidden");
    expect(t.rest).toContain("not in fetchAllowHosts");
    expect(events).toContainEqual(expect.objectContaining({ verdict: "deny", why: "not-listed", method: "CONNECT" }));
    const bad = await tunnel(p, "no-port-here");
    expect(bad.status).toBe("HTTP/1.1 403 Forbidden");
    t.s.destroy();
    bad.s.destroy();
    await p.close();
  });
  it("a tunnel that crosses the byte budget is closed, and the host stays refused", async () => {
    const { p, events } = await proxy({ budgets: { ...defaultConfig().budgets, untrusted: { ...defaultConfig().budgets.untrusted, bytesPerHost: 4096 } } }, { port: () => echoPort });
    const t = await tunnel(p, "allowed.test:443");
    t.s.write(buildClientHello("allowed.test"));
    t.s.on("data", () => undefined);
    for (let i = 0; i < 10 && !t.s.destroyed; i++) {
      t.s.write(Buffer.alloc(1024, 1));
      await new Promise((r) => setTimeout(r, 10));
    }
    await closed(t.s);
    expect(events).toContainEqual(expect.objectContaining({ type: "budget", host: "allowed.test", hit: expect.objectContaining({ rule: "FW-BUDGET-BYTES", key: "bytes:allowed.test" }) }));
    const again = await tunnel(p, "allowed.test:443");
    expect(again.status).toBe("HTTP/1.1 403 Forbidden");
    again.s.destroy();
    await p.close();
  });
  it("send hosts are not counted", async () => {
    const { p, events } = await proxy({ budgets: { ...defaultConfig().budgets, untrusted: { ...defaultConfig().budgets.untrusted, bytesPerHost: 100 } } }, { sendHosts: ["model.test"], port: () => echoPort });
    const t = await tunnel(p, "model.test:443");
    t.s.write(buildClientHello("model.test"));
    t.s.write(Buffer.alloc(5000, 2));
    await new Promise((r) => setTimeout(r, 100));
    expect(t.s.destroyed).toBe(false);
    expect(events.filter((e) => e.type === "budget")).toEqual([]);
    t.s.destroy();
    await p.close();
  });
  it("the request budget refuses the 41st connection to one host in 10 minutes", async () => {
    let now = 0;
    const { policy } = runNetPolicy({ ...defaultConfig(), fetchAllowHosts: ["allowed.test"] });
    const events: ProxyEvent[] = [];
    const p = await startProxy({ policy, budgets: new RunBudgets(policy), listen: { host: "127.0.0.1" }, onEvent: (e) => events.push(e), dial: toLocal(() => webPort), now: () => now++ });
    for (let i = 0; i < 40; i++) expect((await get(p, "http://allowed.test/")).status).toBe(200);
    const r = await get(p, "http://allowed.test/");
    expect(r.status).toBe(403);
    expect(events).toContainEqual(expect.objectContaining({ type: "budget", hit: expect.objectContaining({ rule: "FW-BUDGET-REQUESTS" }) }));
    await p.close();
  });
});

describe("the real dial with a stub resolver (DNS rebinding to private ranges)", () => {
  /** A resolver that answers from a table and counts lookups; connectTo records the address and reaches the local web server. */
  const rig = (table: Record<string, string[]>) => {
    const lookups: string[] = [];
    const dialed: string[] = [];
    const resolve = (h: string): Promise<{ address: string; family: number }[]> => {
      lookups.push(h);
      return Promise.resolve((table[h] ?? []).map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));
    };
    const connectTo = (address: string, _family: number, _port: number): Socket => {
      dialed.push(address);
      return connect(webPort, "127.0.0.1");
    };
    return { lookups, dialed, resolve, connectTo };
  };
  const start = async (cfg: Partial<FirewallConfig>, r: ReturnType<typeof rig>, loopback = false): Promise<{ p: RunningProxy; events: ProxyEvent[] }> => {
    const { policy } = runNetPolicy({ ...defaultConfig(), ...cfg });
    const events: ProxyEvent[] = [];
    const p = await startProxy({ policy, budgets: new RunBudgets(policy), listen: { host: "127.0.0.1" }, onEvent: (e) => events.push(e), resolve: r.resolve, connectTo: r.connectTo, localAnswers: { loopback, privateHosts: cfg.run?.privateHosts ?? [] } });
    return { p, events };
  };
  it("refuses an allowlisted public name that resolves to any private, CGNAT, ULA or mapped address, without connecting", async () => {
    for (const bad of ["10.0.0.5", "172.20.1.1", "192.168.1.1", "100.64.0.1", "fd00::1", "::ffff:10.0.0.5", "127.0.0.1", "169.254.169.254", "0.0.0.0", "fe80::1", "::1"]) {
      const r = rig({ "allowed.test": [bad] });
      const { p, events } = await start({ fetchAllowHosts: ["allowed.test"] }, r);
      const res = await get(p, "http://allowed.test/");
      expect(res.status, bad).toBe(403);
      expect(res.body, bad).toContain(`resolves to ${bad}`);
      expect(events, bad).toContainEqual(expect.objectContaining({ verdict: "deny", why: "resolves-internal", host: "allowed.test" }));
      expect(r.dialed, bad).toEqual([]);
      await p.close();
    }
  });
  it("checks every answer: one private address among public ones refuses the name (order does not matter)", async () => {
    for (const answers of [["93.184.216.34", "10.0.0.5"], ["10.0.0.5", "93.184.216.34"], ["2606:4700::1", "fd00::7"]]) {
      const r = rig({ "allowed.test": answers });
      const { p } = await start({ fetchAllowHosts: ["allowed.test"] }, r);
      expect((await get(p, "http://allowed.test/")).status, answers.join(",")).toBe(403);
      expect(r.dialed).toEqual([]);
      await p.close();
    }
  });
  it("connects to the checked address, after exactly one lookup", async () => {
    const r = rig({ "allowed.test": ["93.184.216.34", "93.184.216.35"] });
    const { p } = await start({ fetchAllowHosts: ["allowed.test"] }, r);
    const res = await get(p, "http://allowed.test/x");
    expect(res.status).toBe(200);
    expect(res.body).toBe("web GET allowed.test /x 0");
    expect(r.lookups).toEqual(["allowed.test"]);
    expect(r.dialed).toEqual(["93.184.216.34"]);
    await p.close();
  });
  it("a CONNECT tunnel is refused the same way", async () => {
    const r = rig({ "allowed.test": ["192.168.0.2"] });
    const { p } = await start({ fetchAllowHosts: ["allowed.test"] }, r);
    const t = await tunnel(p, "allowed.test:443");
    expect(t.status).toContain("403");
    expect(r.dialed).toEqual([]);
    t.s.destroy();
    await p.close();
  });
  it("run.privateHosts admits private answers for the listed name only; loopback and metadata stay refused", async () => {
    const r = rig({ "git.corp.test": ["10.1.2.3"], "allowed.test": ["10.1.2.3"], "evil.corp.test": ["169.254.169.254"], "lo.corp.test": ["127.0.0.1"] });
    const { p } = await start({ fetchAllowHosts: ["corp.test", "allowed.test"], run: { privateHosts: ["corp.test"] } }, r);
    expect((await get(p, "http://git.corp.test/")).status).toBe(200);
    expect(r.dialed).toEqual(["10.1.2.3"]);
    expect((await get(p, "http://allowed.test/")).status).toBe(403);
    expect((await get(p, "http://evil.corp.test/")).status).toBe(403);
    expect((await get(p, "http://lo.corp.test/")).status).toBe(403);
    expect(r.dialed).toEqual(["10.1.2.3"]);
    await p.close();
  });
  it("a name in run.privateHosts but not in the allow lists is still not admitted", async () => {
    const r = rig({ "git.corp.test": ["10.1.2.3"] });
    const { p, events } = await start({ fetchAllowHosts: ["allowed.test"], run: { privateHosts: ["corp.test"] } }, r);
    expect((await get(p, "http://git.corp.test/")).status).toBe(403);
    expect(events).toContainEqual(expect.objectContaining({ why: "not-listed" }));
    expect(r.lookups).toEqual([]);
    await p.close();
  });
  it("--allow-localhost (macOS) admits a loopback answer, not a private one", async () => {
    const r = rig({ "dev.test": ["127.0.0.1"], "allowed.test": ["10.0.0.1"] });
    const { p } = await start({ fetchAllowHosts: ["dev.test", "allowed.test"] }, r, true);
    expect((await get(p, "http://dev.test/")).status).toBe(200);
    expect((await get(p, "http://allowed.test/")).status).toBe(403);
    await p.close();
  });
});

describe("the real dial", () => {
  it("refuses a name that resolves to loopback (DNS rebinding), without connecting", async () => {
    await expect(checkedDial("localhost", 80)).rejects.toBeInstanceOf(DialRefused);
  });
  it("parseAuthority", () => {
    expect(parseAuthority("github.com:443")).toEqual({ host: "github.com", port: 443 });
    expect(parseAuthority("[::1]:443")).toEqual({ host: "::1", port: 443 });
    expect(parseAuthority("github.com")).toBeNull();
    expect(parseAuthority("a:b:443")).toBeNull();
  });
});

describe("the Linux bridge (run here without bubblewrap)", () => {
  it("forwards 127.0.0.1:<port> to the proxy's Unix socket, runs the command and passes its exit status", async () => {
    const dir = mkdtempSync(join(tmpdir(), "lsfw-b-"));
    const sock = join(dir, "p.sock");
    const { policy } = runNetPolicy({ ...defaultConfig(), fetchAllowHosts: ["allowed.test"] });
    const p = await startProxy({ policy, budgets: new RunBudgets(policy), listen: { path: sock }, onEvent: () => undefined, dial: toLocal(() => webPort) });
    // A free port for the bridge on this machine's loopback (inside bubblewrap every port is free).
    const free = await new Promise<number>((r) => {
      const s = createServer().listen(0, "127.0.0.1", () => {
        const port = (s.address() as { port: number }).port;
        s.close(() => r(port));
      });
    });
    const client = `const http=require("http");const q=http.request({host:"127.0.0.1",port:${free},path:"http://allowed.test/b",headers:{host:"allowed.test"}},r=>{let b="";r.on("data",c=>b+=c);r.on("end",()=>{console.log(r.statusCode+" "+b);process.exit(7)})});q.on("error",e=>{console.log("ERR "+e.code);process.exit(1)});q.end();`;
    const out = await new Promise<{ code: number | null; stdout: string }>((res) => {
      const c = spawn(process.execPath, ["-e", BRIDGE_SOURCE, BRIDGE_MARKER, sock, String(free), "--", process.execPath, "-e", client], { stdio: ["ignore", "pipe", "pipe"] });
      let o = "";
      c.stdout.on("data", (d: Buffer) => (o += d.toString()));
      c.on("close", (code) => res({ code, stdout: o }));
    });
    expect(out.stdout.trim()).toBe("200 web GET allowed.test /b 0");
    expect(out.code).toBe(7);
    await p.close();
    rmSync(dir, { recursive: true, force: true });
  });
  it("exits 127 when the command does not exist", async () => {
    const code = await new Promise<number | null>((res) => {
      const c = spawn(process.execPath, ["-e", BRIDGE_SOURCE, BRIDGE_MARKER, "/nonexistent.sock", "0", "--", "/no/such/program"], { stdio: "ignore" });
      c.on("close", (x) => res(x));
    });
    expect(code).toBe(127);
  });
});

describe("LG1: a connection is made only once its decision is recorded", () => {
  async function refusing(): Promise<{ p: RunningProxy; dialed: () => number }> {
    const { policy } = runNetPolicy({ ...defaultConfig(), fetchAllowHosts: ["allowed.test"] });
    let dialed = 0;
    const dial = (h: string, port: number): Promise<Socket> => {
      dialed++;
      return toLocal(() => webPort)(h, port);
    };
    // onEvent answers false for an allow: the log refused its entry and the fallback entry.
    const p = await startProxy({ policy, budgets: new RunBudgets(policy), listen: { host: "127.0.0.1" }, onEvent: (e) => !(e.type === "net" && e.verdict === "allow"), dial, helloTimeoutMs: 500 });
    return { p, dialed: () => dialed };
  }

  it("HTTP: refused with 403 and FW-LOG-UNRECORDED, without dialing", async () => {
    const { p, dialed } = await refusing();
    const r = await get(p, "http://allowed.test/x");
    expect(r.status).toBe(403);
    expect(r.body).toContain("FW-LOG-UNRECORDED");
    expect(dialed()).toBe(0);
    expect(p.stats()[0]).toMatchObject({ host: "allowed.test", conns: 0, refused: 1 });
    await p.close();
  });

  it("CONNECT: refused with 403 and FW-LOG-UNRECORDED, without dialing", async () => {
    const { p, dialed } = await refusing();
    const t = await tunnel(p, "allowed.test:443");
    expect(t.status).toBe("HTTP/1.1 403 Forbidden");
    expect(t.rest).toContain("FW-LOG-UNRECORDED");
    expect(dialed()).toBe(0);
    t.s.destroy();
    await p.close();
  });
});
