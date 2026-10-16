import { describe, expect, it } from "vitest";
import { actionFingerprint } from "../engine/fingerprint.js";
import { createDownloadGate, downloadSnapshot, holdOnDeterminingFilename, isExecutableItem } from "./downloads.js";

const OURS = "ourextensionidourextensionidabcd";
const exe = { id: 1, url: "https://files.test/dl/setup.exe", filename: "setup.exe", mime: "application/x-msdownload" };

describe("isExecutableItem", () => {
  it("by offered name, by MIME, and by the URL's last segment when the name is generic", () => {
    expect(isExecutableItem(exe)).toBe(true);
    expect(isExecutableItem({ id: 2, url: "https://files.test/get?id=9", filename: "download", mime: "application/x-apple-diskimage" })).toBe(true);
    expect(isExecutableItem({ id: 3, url: "https://files.test/tool.msi", filename: "download", mime: "application/octet-stream" })).toBe(true);
    expect(isExecutableItem({ id: 4, url: "https://files.test/report.docm", filename: "report.docm" })).toBe(true);
  });
  it("not for documents and images", () => {
    expect(isExecutableItem({ id: 5, url: "https://files.test/notes.txt", filename: "notes.txt", mime: "text/plain" })).toBe(false);
    expect(isExecutableItem({ id: 6, url: "https://files.test/photo.jpg", filename: "photo.jpg", mime: "image/jpeg" })).toBe(false);
  });
});

describe("download gate", () => {
  it("holds an executable and lets a benign file through", () => {
    const g = createDownloadGate({ extensionId: OURS });
    expect(g.intercept(exe)).toEqual({ url: exe.url, filename: "setup.exe", mime: "application/x-msdownload" });
    expect(g.intercept({ id: 2, url: "https://files.test/a.pdf", filename: "a.pdf", mime: "application/pdf" })).toBeNull();
  });

  it("an approved URL passes once, only for our own re-download, only within the window", () => {
    let t = 0;
    const g = createDownloadGate({ extensionId: OURS, now: () => t });
    g.allowOnce(exe.url);
    // A page or another extension starting the same URL is still held.
    expect(g.intercept({ ...exe, byExtensionId: "someoneelse" })).not.toBeNull();
    expect(g.intercept(exe)).not.toBeNull();
    expect(g.intercept({ ...exe, byExtensionId: OURS })).toBeNull();
    // Spent.
    expect(g.intercept({ ...exe, byExtensionId: OURS })).not.toBeNull();
    g.allowOnce(exe.url);
    t += 61_000;
    expect(g.intercept({ ...exe, byExtensionId: OURS })).not.toBeNull();
  });

  it("I10: the listener returns true for a held download, cancels it, and only then calls suggest()", async () => {
    const g = createDownloadGate({ extensionId: OURS });
    const order: string[] = [];
    let finishCancel: () => void = () => undefined;
    const held: unknown[] = [];
    const listener = holdOnDeterminingFilename(g, {
      cancel: (id) => {
        order.push(`cancel:${id}`);
        return new Promise<void>((ok) => (finishCancel = ok));
      },
      hold: (d) => void held.push(d),
    });
    const suggest = (s?: { filename: string }) => void order.push(`suggest:${s === undefined ? "none" : s.filename}`);
    expect(listener(exe, suggest)).toBe(true);
    expect(held).toHaveLength(1);
    // Chrome waits for suggest; it is not called before the cancel has gone through.
    expect(order).toEqual(["cancel:1"]);
    finishCancel();
    await Promise.resolve();
    await Promise.resolve();
    expect(order).toEqual(["cancel:1", "suggest:none"]);
    // A benign download: nothing returned, nothing cancelled.
    expect(listener({ id: 9, url: "https://files.test/a.pdf", filename: "a.pdf", mime: "application/pdf" }, suggest)).toBeUndefined();
    expect(order).toHaveLength(2);
  });

  it("I10: a failed cancel still releases Chrome's wait", async () => {
    const g = createDownloadGate({ extensionId: OURS });
    let suggested = false;
    const listener = holdOnDeterminingFilename(g, { cancel: () => Promise.reject(new Error("gone")), hold: () => undefined });
    expect(listener(exe, () => void (suggested = true))).toBe(true);
    await new Promise((r) => setTimeout(r, 0));
    expect(suggested).toBe(true);
  });

  it("m5: scripts, installers and shortcuts beyond the first list are held; archives are not (documented)", () => {
    for (const name of ["policy.reg", "fix.msp", "run.pif", "app.application", "tool.appref-ms", "ext.vsix", "help.chm", "start.jnlp", "a.scpt", "go.workflow", "x.snap", "s.wsh", "l.library-ms", "s.settingcontent-ms", "d.diagcab", "k.xll", "b.xlsb", "p.ppsm", "q.potm", "i.inf", "m.msc", "u.url", "z.scf"]) {
      expect(isExecutableItem({ id: 1, url: `https://files.test/${name}`, filename: name }), name).toBe(true);
    }
    for (const name of ["a.zip", "a.7z", "a.tar.gz", "a.rar"]) expect(isExecutableItem({ id: 1, url: `https://files.test/${name}`, filename: name }), name).toBe(false);
  });

  it("the snapshot binds the URL, name and type", () => {
    const a = downloadSnapshot({ url: exe.url, filename: "setup.exe", mime: exe.mime });
    expect(a).toMatchObject({ tabId: -1, frameId: -1, kind: "download", actionClass: "download_exec", frameOrigin: "https://files.test" });
    const other = downloadSnapshot({ url: "https://files.test/dl/other.exe", filename: "setup.exe", mime: exe.mime });
    const renamed = downloadSnapshot({ url: exe.url, filename: "setup2.exe", mime: exe.mime });
    expect(actionFingerprint(other)).not.toBe(actionFingerprint(a));
    expect(actionFingerprint(renamed)).not.toBe(actionFingerprint(a));
  });
});
