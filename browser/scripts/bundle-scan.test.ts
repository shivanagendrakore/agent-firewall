import { describe, expect, it } from "vitest";
import { disallowed, remoteReferencesInHtml, scanSource } from "./bundle-scan.js";

const names = (code: string): string[] => scanSource("x.js", code).map((f) => f.name);

// These strings are only parsed, never run.
describe("bundle scanner: what it catches", () => {
  it.each([
    ["eval call", 'eval("1+1")', ["eval"]],
    ["new Function", 'const f = new Function("return 1")', ["Function"]],
    ["Function call", 'Function("return 1")()', ["Function"]],
    ["fetch", 'fetch("https://x.test")', ["fetch"]],
    ["self.fetch", 'self.fetch("/a")', ["fetch"]],
    ["globalThis quoted", 'globalThis["fetch"]("/a")', ["fetch"]],
    ["XMLHttpRequest", "new XMLHttpRequest()", ["XMLHttpRequest"]],
    ["WebSocket", 'new WebSocket("ws://x")', ["WebSocket"]],
    ["EventSource", 'new EventSource("/s")', ["EventSource"]],
    ["sendBeacon", 'navigator.sendBeacon("/b", "x")', ["sendBeacon"]],
    ["importScripts", 'importScripts("https://x.test/a.js")', ["importScripts"]],
    ["string timer", 'setTimeout("alert(1)", 5)', ["setTimeout(string)"]],
    ["remote dynamic import", 'import("https://x.test/a.js")', ["import()"]],
    ["computed dynamic import", "import(url)", ["import()"]],
    ["window.eval", "window.eval(code)", ["eval"]],
  ])("%s", (_label, code, want) => {
    expect(names(code)).toEqual(want);
  });
});

describe("bundle scanner: what it leaves alone", () => {
  it("words in comments and strings, our own keys, and function-valued timers", () => {
    expect(names('// fetch the list\nconst s = "fetch eval WebSocket"; const o = { fetch: 1, eval: 2 }; setTimeout(() => 1, 5); import("./local.js");')).toEqual([]);
  });
  it("an allowlisted finding passes and anything else is reported", () => {
    const f = scanSource("worker.js", 'fetch("/a"); eval("1");');
    expect(disallowed(f, [{ file: "worker.js", name: "fetch", reason: "test" }]).map((x) => x.name)).toEqual(["eval"]);
    expect(disallowed(f, [])).toHaveLength(2);
  });
});

describe("html scanner", () => {
  it("flags remote and inline scripts and remote stylesheets", () => {
    expect(remoteReferencesInHtml("a.html", '<script src="https://cdn.test/a.js"></script>').map((f) => f.name)).toEqual(["https://cdn.test/a.js"]);
    expect(remoteReferencesInHtml("a.html", '<link rel="stylesheet" href="//cdn.test/a.css">')).toHaveLength(1);
    expect(remoteReferencesInHtml("a.html", "<script>alert(1)</script>").map((f) => f.name)).toEqual(["inline script"]);
  });
  it("accepts packaged scripts and styles", () => {
    expect(remoteReferencesInHtml("a.html", '<link rel="stylesheet" href="style.css"><script src="popup.js"></script>')).toEqual([]);
  });
});
