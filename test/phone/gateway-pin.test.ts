/**
 * Item P for clients with no hook (the gateway's stdio wrappers): the paired-phones pin travels in the wrapper's
 * own arguments (`--phones sha256:<hex>`, the counterpart of the hook command's LAUNCHSAFE_FIREWALL_PHONES),
 * wrap-config writes it, phone pair and phone remove re-pin it, and the gateway then honours a phone approval
 * exactly as the hook path does. Also: the held item's action code in `queue list`, and one log line for an
 * expired phone approval. Always in temporary homes.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { applyPlan, applyUnwrap, planUnwrap, planWrap, repinGatewayEntries, wrappedPhonePins } from "../../src/gateway/clients.js";
import { pinnedPhonesInArgs, withPhonesArg } from "../../src/gateway/install.js";
import { coreOptionsFor } from "../../src/gateway/stdio.js";
import { installDir } from "../../src/runtime/layout.js";
import { tailLog } from "../../src/runtime/log.js";
import { unwrapFirewall } from "../../src/runtime/pins.js";
import { installedPhonePin, pollOnce, syncOutbox } from "../../src/runtime/relay/daemon.js";
import { phonesPinOf } from "../../src/runtime/relay/phones.js";
import { getQueueItem, listQueue } from "../../src/runtime/store.js";
import { gw, textOf } from "../gateway/harness.js";
import { machine, pairWith, queueSend, retry, TestPhone, type Machine } from "./harness.js";

const CLI = join(installDir(), "dist", "cli.js");
const NODE = process.execPath;
const MIN = 60_000;
const PIN_RE = /^sha256:[0-9a-f]{64}$/;
const fe = (home: string) => ({ home, platform: "darwin" as NodeJS.Platform, env: {} });
const DESKTOP = (home: string) => join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");

function write(p: string, text: string): void {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
}

const SERVERS = {
  mcpServers: {
    gmail: { command: "npx", args: ["-y", "gmail-mcp@1.0.0"], env: { A: "1" } },
    slack: { command: "npx", args: ["-y", "slack-mcp@1.0.0", "--phones", "not-ours"] },
    remote: { url: "https://mcp.example.com/mcp" },
  },
};

function wrapDesktop(m: Machine, client: "claude-desktop" | "codex" = "claude-desktop") {
  const plans = planWrap({ l: m.l, client, node: NODE, cli: CLI, port: 8473 }, fe(m.home));
  for (const p of plans) applyPlan(m.l, p);
  return plans;
}

const argsOf = (home: string, name: string): string[] => (JSON.parse(readFileSync(DESKTOP(home), "utf8")) as typeof SERVERS).mcpServers[name as "gmail"].args;

/** A machine with the firewall data but no hook: the gateway is the only thing in front of the client. */
async function gatewayOnly(): Promise<Machine> {
  const m = await machine({ pair: false });
  rmSync(join(m.l.home, "install.json"));
  write(DESKTOP(m.home), JSON.stringify(SERVERS, null, 2));
  return m;
}

describe("withPhonesArg / pinnedPhonesInArgs", () => {
  const base = [CLI, "mcp", "wrap", "--client", "cursor", "--server", "s", "--mode", "full", "--", "npx", "--phones", "x"];
  const pin = `sha256:${"a".repeat(64)}`;
  it("sets, replaces and removes the pin in the wrapper's head only; the server's own arguments are never read or changed", () => {
    expect(pinnedPhonesInArgs(base)).toBeNull();
    const pinned = withPhonesArg(base, pin);
    expect(pinned.slice(0, 11)).toEqual([CLI, "mcp", "wrap", "--client", "cursor", "--server", "s", "--mode", "full", "--phones", pin]);
    expect(pinned.slice(11)).toEqual(["--", "npx", "--phones", "x"]);
    expect(pinnedPhonesInArgs(pinned)).toBe(pin);
    const other = `sha256:${"b".repeat(64)}`;
    expect(pinnedPhonesInArgs(withPhonesArg(pinned, other))).toBe(other);
    expect(withPhonesArg(withPhonesArg(pinned, null), null)).toEqual(base);
    // Not a wrapper: untouched.
    expect(withPhonesArg(["-y", "x", "--", "y"], pin)).toEqual(["-y", "x", "--", "y"]);
    expect(pinnedPhonesInArgs(["npx", "--phones", pin])).toBeNull();
  });
});

describe("wrap-config carries the pin", () => {
  it("with a phone paired, a JSON wrapper and a Codex wrapper carry the pin the hook command carries; unwrapping still restores the originals", async () => {
    const m = await machine();
    const pin = phonesPinOf(m.l) as string;
    expect(pin).toMatch(PIN_RE);
    write(DESKTOP(m.home), JSON.stringify(SERVERS, null, 2));
    const [plan] = wrapDesktop(m);
    expect(plan?.wrapped.map((w) => w.server)).toEqual(["gmail", "slack", "remote"]);
    const args = argsOf(m.home, "gmail");
    expect(args).toEqual([CLI, "mcp", "wrap", "--client", "claude-desktop", "--server", "gmail", "--mode", "full", "--phones", pin, "--", "npx", "-y", "gmail-mcp@1.0.0"]);
    expect(pinnedPhonesInArgs(args)).toBe(pin);
    // The server's own "--phones not-ours" is not ours and not read as a pin.
    expect(pinnedPhonesInArgs(argsOf(m.home, "slack"))).toBe(pin);
    expect(argsOf(m.home, "slack").slice(-4)).toEqual(["-y", "slack-mcp@1.0.0", "--phones", "not-ours"]);
    // The wrapper is still not a change of the server.
    expect(unwrapFirewall({ command: NODE, args }, CLI)).toEqual({ command: "npx", args: ["-y", "gmail-mcp@1.0.0"] });
    expect(wrappedPhonePins(m.l)).toMatchObject({ pins: [pin, pin], http: true });
    // Codex.
    write(join(m.home, ".codex", "config.toml"), '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp@1.2.3"]\n');
    wrapDesktop(m, "codex");
    const toml = readFileSync(join(m.home, ".codex", "config.toml"), "utf8");
    expect(toml).toContain(`"--phones", "${pin}", "--", "npx"`);
    expect(wrappedPhonePins(m.l).pins).toEqual([pin, pin, pin]);
    for (const c of ["claude-desktop", "codex"] as const) for (const p of planUnwrap(m.l, c)) applyUnwrap(m.l, p);
    expect(JSON.parse(readFileSync(DESKTOP(m.home), "utf8"))).toEqual(SERVERS);
    expect(readFileSync(join(m.home, ".codex", "config.toml"), "utf8")).toBe('[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp@1.2.3"]\n');
    await m.relay.close();
  });

  it("with no phone paired the wrapper is exactly what it was before (no pin)", async () => {
    const m = await machine({ pair: false });
    write(DESKTOP(m.home), JSON.stringify(SERVERS, null, 2));
    wrapDesktop(m);
    expect(argsOf(m.home, "gmail")).toEqual([CLI, "mcp", "wrap", "--client", "claude-desktop", "--server", "gmail", "--mode", "full", "--", "npx", "-y", "gmail-mcp@1.0.0"]);
    await m.relay.close();
  });
});

describe("phone pair and phone remove re-pin the wrappers", () => {
  it("a gateway-only client: pairing after wrap-config pins the wrappers, removing the last phone unpins them, the install record follows", async () => {
    const m = await gatewayOnly();
    wrapDesktop(m);
    expect(pinnedPhonesInArgs(argsOf(m.home, "gmail"))).toBeNull();
    write(join(m.home, ".codex", "config.toml"), '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp@1.2.3"]\n');
    wrapDesktop(m, "codex");
    const r = await pairWith(m, m.phone);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain("Wrapped MCP servers now carry the pin");
    const pin = phonesPinOf(m.l) as string;
    expect(pinnedPhonesInArgs(argsOf(m.home, "gmail"))).toBe(pin);
    expect(pinnedPhonesInArgs(argsOf(m.home, "slack"))).toBe(pin);
    expect(readFileSync(join(m.home, ".codex", "config.toml"), "utf8")).toContain(`"--phones", "${pin}"`);
    expect(wrappedPhonePins(m.l).pins).toEqual([pin, pin, pin]);
    // No hook anywhere, yet the daemon has a pin to check phones.json against.
    expect(installedPhonePin(m.l).pin).toBe(pin);
    // A second phone changes the list: the pin follows.
    const second = new TestPhone("iPad");
    expect((await pairWith(m, second)).status).toBe(0);
    const pin2 = phonesPinOf(m.l) as string;
    expect(pin2).not.toBe(pin);
    expect(wrappedPhonePins(m.l).pins).toEqual([pin2, pin2, pin2]);
    // Removing one phone, then the last.
    expect((await m.cli(["phone", "remove", "iPad"])).status).toBe(0);
    expect(pinnedPhonesInArgs(argsOf(m.home, "gmail"))).toBe(pin);
    const last = await m.cli(["phone", "remove", "Pixel"]);
    expect(last.status, last.stderr).toBe(0);
    expect(wrappedPhonePins(m.l).pins).toEqual([null, null, null]);
    expect(argsOf(m.home, "gmail")).toEqual([CLI, "mcp", "wrap", "--client", "claude-desktop", "--server", "gmail", "--mode", "full", "--", "npx", "-y", "gmail-mcp@1.0.0"]);
    // The record's hash follows every rewrite, so unwrap still restores the originals and sees no drift.
    const plans = planUnwrap(m.l, "claude-desktop");
    expect(plans.flatMap((p) => p.notes)).toEqual([]);
    for (const p of plans) applyUnwrap(m.l, p);
    expect(JSON.parse(readFileSync(DESKTOP(m.home), "utf8"))).toEqual(SERVERS);
    await m.relay.close();
  });

  it("an entry changed since it was wrapped is reported and left as it is; the others are re-pinned", async () => {
    const m = await gatewayOnly();
    wrapDesktop(m);
    const doc = JSON.parse(readFileSync(DESKTOP(m.home), "utf8")) as typeof SERVERS;
    doc.mcpServers.slack.args.push("--extra");
    write(DESKTOP(m.home), JSON.stringify(doc, null, 2));
    const r = await pairWith(m, m.phone);
    expect(r.stdout).toMatch(/Could not update MCP server "slack".*changed since it was wrapped/);
    const pin = phonesPinOf(m.l) as string;
    expect(pinnedPhonesInArgs(argsOf(m.home, "gmail"))).toBe(pin);
    expect(pinnedPhonesInArgs(argsOf(m.home, "slack"))).toBeNull();
    expect(argsOf(m.home, "slack").at(-1)).toBe("--extra");
    // Doctor-visible: one wrapper behind.
    expect(wrappedPhonePins(m.l).pins.filter((x) => x !== pin)).toHaveLength(1);
    await m.relay.close();
  });

  it("re-pinning with the pin already in place changes nothing and writes nothing", async () => {
    const m = await gatewayOnly();
    wrapDesktop(m);
    expect((await pairWith(m, m.phone)).status).toBe(0);
    const before = readFileSync(DESKTOP(m.home), "utf8");
    expect(repinGatewayEntries(m.l, phonesPinOf(m.l))).toEqual({ updated: [], skipped: [] });
    expect(readFileSync(DESKTOP(m.home), "utf8")).toBe(before);
    await m.relay.close();
  });
});

describe("the gateway honours a phone approval as the hook does", () => {
  it("a held call in a wrapped server (no hook installed) is approved from the phone and runs once; the pin comes from the wrapper's arguments", async () => {
    const m = await gatewayOnly();
    wrapDesktop(m);
    expect((await pairWith(m, m.phone)).status).toBe(0);
    const pin = phonesPinOf(m.l) as string;
    // What `mcp wrap` does with the arguments in the client's file.
    const { options } = coreOptionsFor({ l: m.l, env: { HOME: m.home }, client: "claude-desktop", server: "slack", mode: "auto", cwd: m.ws, home: m.home, transport: "stdio", phonesPin: pinnedPhonesInArgs(argsOf(m.home, "slack")) as string });
    expect(options.env.LAUNCHSAFE_FIREWALL_PHONES).toBe(pin);
    expect(options.env.HOME).toBe(m.home);
    const mail = gw({ l: m.l, home: m.home, server: "gmail", session: "desk", core: { env: options.env }, cfg: { era: "modern", tools: [{ name: "get_message", description: "Read a message.", inputSchema: { type: "object" } }] } });
    mail.call("tools/list");
    mail.call("tools/call", { name: "get_message", arguments: { id: "m1" } });
    const slack = gw({ l: m.l, home: m.home, server: "slack", session: "desk", core: { env: options.env }, cfg: { era: "modern", tools: [{ name: "post_message", description: "Post.", inputSchema: { type: "object" } }] } });
    slack.call("tools/list");
    const args = { name: "post_message", arguments: { channel: "#general", text: "summary" } };
    const held = slack.call("tools/call", args);
    expect(textOf(held)).toMatch(/queue approve [a-z0-9]+/);
    const id = /queue approve ([a-z0-9]+)/.exec(textOf(held))?.[1] as string;
    // The item goes to the phone (the daemon's pin comes from the wrappers: there is no hook), the phone approves.
    await syncOutbox(m.daemon());
    const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === id);
    expect(entry).toBeDefined();
    m.relay.addDecision(m.phone.decide(entry as NonNullable<typeof entry>, "approve"));
    expect(await pollOnce(m.daemon(), 0)).toMatchObject({ received: 1, applied: 1, refused: 0 });
    expect(getQueueItem(m.l, id)).toMatchObject({ status: "approved", decidedBy: "phone: Pixel" });
    const second = slack.call("tools/call", args);
    expect(second.result?.isError).not.toBe(true);
    expect(textOf(second)).toBe("ok post_message");
    expect(slack.up.received.filter((x) => x.method === "tools/call")).toHaveLength(1);
    expect(tailLog(m.l, 30).some((e) => e.event.type === "decision" && e.event.via === "phone" && Array.isArray(e.event.rules) && e.event.rules.includes("FW-APPROVED"))).toBe(true);
    // Once: the same call is held again.
    expect(textOf(slack.call("tools/call", args))).toMatch(/queue approve/);
    await m.relay.close();
  });

  it("with the wrapper's pin missing the approval is not honoured, and the call stays held for the terminal", async () => {
    const m = await machine();
    const mail = gw({ l: m.l, home: m.home, server: "gmail", session: "nopin", cfg: { era: "modern", tools: [{ name: "get_message", description: "Read.", inputSchema: { type: "object" } }] } });
    mail.call("tools/list");
    mail.call("tools/call", { name: "get_message", arguments: { id: "m1" } });
    const slack = gw({ l: m.l, home: m.home, server: "slack", session: "nopin", cfg: { era: "modern", tools: [{ name: "post_message", description: "Post.", inputSchema: { type: "object" } }] } });
    slack.call("tools/list");
    const args = { name: "post_message", arguments: { channel: "#general", text: "summary" } };
    const id = /queue approve ([a-z0-9]+)/.exec(textOf(slack.call("tools/call", args)))?.[1] as string;
    await syncOutbox(m.daemon());
    const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === id) as NonNullable<ReturnType<TestPhone["inbox"]>[number]>;
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    await pollOnce(m.daemon(), 0);
    const again = slack.call("tools/call", args);
    expect(again.result?.isError).toBe(true);
    expect(slack.up.received.filter((x) => x.method === "tools/call")).toHaveLength(0);
    await m.relay.close();
  });
});

describe("queue list shows the action code", () => {
  it("each held item's line carries the 6-character code the phone shows", async () => {
    const m = await machine();
    const { item } = queueSend(m);
    await syncOutbox(m.daemon());
    const phoneCode = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id)?.item.code;
    expect(phoneCode).toBe(item.actionHash.slice(0, 6));
    const text = await m.cli(["queue", "list"]);
    expect(text.status).toBe(0);
    expect(text.stdout.replace(/\s+/g, " ")).toContain(`${item.id} · code ${phoneCode} ·`);
    const json = JSON.parse((await m.cli(["queue", "list", "--json"])).stdout) as { id: string; actionHash: string }[];
    expect(json.find((i) => i.id === item.id)?.actionHash.slice(0, 6)).toBe(phoneCode);
    await m.relay.close();
  });
});

describe("an expired phone approval is logged once in the hook", () => {
  it("the hook logs it on the first call after it lapsed, not again, and the decision is the same as before", async () => {
    const m = await machine();
    const { item } = queueSend(m);
    await syncOutbox(m.daemon());
    const entry = m.phone.inbox(m.relay).find((e) => e.item.itemId === item.id) as NonNullable<ReturnType<TestPhone["inbox"]>[number]>;
    m.relay.addDecision(m.phone.decide(entry, "approve"));
    await pollOnce(m.daemon(), 0);
    const expiredLines = (): Record<string, unknown>[] => tailLog(m.l, 200).map((e) => e.event).filter((e) => e.type === "phone_approval_expired");
    // Within the window: nothing logged.
    const now = Date.now();
    expect(retry(m, "s1", "git push origin main", { now: new Date(now + 5 * MIN) }).d).toBe("allow");
    expect(expiredLines()).toHaveLength(0);
    // Held again (approval used); a second approval for a second call, then let it lapse.
    const later = new Date(now + 90 * MIN);
    const a = retry(m, "s1", "git push origin main", { now: later });
    expect(a.d).not.toBe("allow");
    expect(expiredLines()).toHaveLength(1);
    expect(expiredLines()[0]).toMatchObject({ queue: item.id, session: "s1", action: item.actionHash });
    const b = retry(m, "s1", "git push origin main", { now: new Date(now + 91 * MIN) });
    expect(b.d).toBe(a.d);
    expect(b.reason).toBe(a.reason);
    expect(expiredLines()).toHaveLength(1);
    expect(listQueue(m.l).items.some((i) => i.status === "pending")).toBe(true);
    await m.relay.close();
  });
});
