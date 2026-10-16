/**
 * Unit tests for the detectors the rules are built on: paths, network,
 * secrets, personal data, unicode, SQL and the glob matcher. Positive and
 * negative cases for each, including the tricky encodings attackers use.
 */

import { describe, expect, it } from "vitest";
import { globMatch } from "../src/engine/glob.js";
import { classifyPath, normalizeAbs, resolvePath } from "../src/engine/paths.js";
import { entropy, hostMatches, isDnsExfilShape, isLoopback, isMetadataEndpoint, isRawIp, parseUrlLike, urlCarriesData } from "../src/engine/network.js";
import { containsFingerprint, credentialAssignments, fingerprint, findSecrets, isPlaceholder, redactSecrets } from "../src/engine/secrets.js";
import { findCards, findIbans, findNationalIds, ibanValid, luhnValid, verhoeffValid } from "../src/engine/pii.js";
import { invisibleCharacters, stripInvisible } from "../src/engine/unicode.js";
import { classifySql } from "../src/engine/sql.js";
import { defaultConfig } from "../src/policy.js";
import { addEffect, downloadsOf, newCollector } from "../src/engine/effects.js";
import { emptyState, foldEvents } from "../src/engine/state.js";
import { decide } from "../src/engine/decide.js";
import { NETWORK_REFUSED_TOOL } from "../src/engine/classify.js";
import type { Effect } from "../src/types.js";
import { ctx } from "./helpers.js";

describe("glob", () => {
  it("* does not cross directories", () => {
    expect(globMatch("src/*.ts", "src/a.ts", false)).toBe(true);
    expect(globMatch("src/*.ts", "src/x/a.ts", false)).toBe(false);
  });
  it("** crosses directories", () => {
    expect(globMatch("**/CLAUDE.md", "/a/b/CLAUDE.md", false)).toBe(true);
    expect(globMatch("**/CLAUDE.md", "/CLAUDE.md", false)).toBe(true);
  });
  it("{a,b} alternates", () => {
    expect(globMatch("x.{ts,js}", "x.ts", false)).toBe(true);
    expect(globMatch("x.{ts,js}", "x.py", false)).toBe(false);
  });
  it("is case sensitive or not as asked", () => {
    expect(globMatch("**/claude.md", "/A/CLAUDE.md", true)).toBe(true);
    expect(globMatch("**/claude.md", "/A/CLAUDE.md", false)).toBe(false);
  });
});

describe("path resolution", () => {
  it("normalizes . and ..", () => expect(normalizeAbs("/a/b/../c/./d")).toBe("/a/c/d"));
  it("expands ~ and $HOME", () => {
    expect(resolvePath("~/x", { cwd: "/w", home: "/Users/d" })?.abs).toBe("/Users/d/x");
    expect(resolvePath("$HOME/.ssh", { cwd: "/w", home: "/Users/d" })?.abs).toBe("/Users/d/.ssh");
  });
  it("marks a variable path inexact", () => expect(resolvePath("$TARGET/x", { cwd: "/w", home: "/h" })?.exact).toBe(false));
  it("flags a glob only in the last segment", () => {
    expect(resolvePath("src/*.ts", { cwd: "/w", home: "/h" })?.glob).toBe(true);
    expect(resolvePath("*/x.ts", { cwd: "/w", home: "/h" })?.glob).toBe(false);
  });
});

describe("path classification", () => {
  const cfg = defaultConfig();
  const c = ctx();
  const classify = (p: string) => classifyPath(resolvePath(p, c)!, c, cfg);
  it("protects CLAUDE.md anywhere", () => expect(classify("/Users/dev/proj/sub/CLAUDE.md").protected).toBe(true));
  it("protects .claude recursively", () => expect(classify("/Users/dev/proj/.claude/settings.json").protected).toBe(true));
  it("treats .env as a secret inside the workspace", () => expect(classify("/Users/dev/proj/.env").secret).toBe(true));
  it("treats ~/.aws as a credential store", () => expect(classify("/Users/dev/.aws/credentials").credentialStore).toBe(true));
  it("does not treat .env.example as a secret", () => expect(classify("/Users/dev/proj/.env.example").secret).toBe(false));
  it("marks files outside the workspace as outside", () => expect(classify("/etc/hosts").zone).toBe("outside"));
  it("marks .git/hooks as persistence", () => expect(classify("/Users/dev/proj/.git/hooks/pre-commit").persistence).toBe(true));
  it("a glob at root matches CLAUDE.md through the sensitive base-name expansion", () => {
    expect(classifyPath(resolvePath("/Users/dev/proj/*", c)!, c, cfg).protected).toBe(true);
  });
});

describe("network", () => {
  it("normalizes obfuscated IPv4 to dotted form", () => {
    expect(parseUrlLike("http://0x7f000001/")?.host).toBe("127.0.0.1");
    expect(parseUrlLike("http://2130706433/")?.host).toBe("127.0.0.1");
  });
  it("detects loopback and metadata", () => {
    expect(isLoopback("127.0.0.1")).toBe(true);
    expect(isLoopback("localhost")).toBe(true);
    expect(isMetadataEndpoint("169.254.169.254")).toBe(true);
    expect(isMetadataEndpoint("metadata.google.internal")).toBe(true);
  });
  it("raw IP but not loopback", () => {
    expect(isRawIp("8.8.8.8")).toBe(true);
    expect(isRawIp("127.0.0.1")).toBe(false);
  });
  it("hostMatches covers subdomains, exact and wildcard", () => {
    expect(hostMatches("api.github.com", "github.com")).toBe(true);
    expect(hostMatches("github.com", "=github.com")).toBe(true);
    expect(hostMatches("github.com", "*.github.com")).toBe(false);
    expect(hostMatches("notgithub.com", "github.com")).toBe(false);
  });
  it("detects DNS-exfil-shaped host names", () => {
    expect(isDnsExfilShape("d4e5f6a7b8c9d0e1f2a3b4c5.collector.example.com")).toBe(true);
    expect(isDnsExfilShape("api.github.com")).toBe(false);
    expect(isDnsExfilShape("my-cool-preview-deploy.vercel.app")).toBe(false);
  });
  it("detects a URL carrying data", () => {
    expect(urlCarriesData(parseUrlLike("https://x.example.com/p?d=" + "A1b2".repeat(20))!)).toBe(true);
    expect(urlCarriesData(parseUrlLike("https://x.example.com/users/42")!)).toBe(false);
  });
  it("entropy is higher for random strings", () => expect(entropy("aaaaaaaa")).toBeLessThan(entropy("a9Xk2Lpq")));
});

describe("secrets", () => {
  it("finds known shapes", () => {
    expect(findSecrets("x AKIA1A2B3C4D5E6F7G8H y").map((s) => s.name)).toContain("AWS access key id");
    expect(findSecrets("ghp_0123456789abcdefghijklmnopqrstuvwxyz").length).toBe(1);
  });
  it("ignores placeholders", () => {
    expect(isPlaceholder("your-api-key-here")).toBe(true);
    expect(isPlaceholder("${API_KEY}")).toBe(true);
    expect(isPlaceholder("sk-xxxxxxxxxxxx")).toBe(true);
  });
  it("reads credential assignments from env dumps", () => {
    expect(credentialAssignments("DATABASE_URL=postgres://u:p@h/db\nPORT=3000")).toEqual(["postgres://u:p@h/db"]);
  });
  it("fingerprints match the secret even base64/hex/url-encoded", () => {
    const secret = "AKIA1A2B3C4D5E6F7G8H";
    const fp = fingerprint(secret)!;
    expect(containsFingerprint(secret, [fp])).toBe(true);
    expect(containsFingerprint(Buffer.from(secret).toString("base64"), [fp])).toBe(true);
    expect(containsFingerprint(Buffer.from(secret).toString("hex"), [fp])).toBe(true);
    expect(containsFingerprint(encodeURIComponent(secret), [fp])).toBe(true);
    expect(containsFingerprint("unrelated text", [fp])).toBe(false);
  });
  it("fingerprints match a secret split across DNS labels", () => {
    const secret = "abcdef0123456789";
    expect(containsFingerprint("abcdef.0123456789.evil.example.com", [fingerprint(secret)!])).toBe(true);
  });
  it("redacts but keeps four characters", () => {
    const out = redactSecrets("key AKIA1A2B3C4D5E6F7G8H end");
    expect(out.count).toBe(1);
    expect(out.text).toContain("AKIA");
    expect(out.text).not.toContain("AKIA1A2B3C4D5E6F7G8H");
  });
});

describe("personal and financial data", () => {
  it("Luhn", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("4111111111111112")).toBe(false);
  });
  it("finds valid cards only", () => {
    expect(findCards("pay 4111111111111111 now").length).toBe(1);
    expect(findCards("order 1234567890123456").length).toBe(0);
    expect(findCards("ts 17299999999999 x").length).toBe(0);
  });
  it("IBAN mod-97", () => {
    expect(ibanValid("DE89370400440532013000")).toBe(true);
    expect(ibanValid("DE89370400440532013001")).toBe(false);
    expect(findIbans("send to GB82WEST12345698765432 today").length).toBe(1);
  });
  it("Verhoeff for Aadhaar", () => {
    expect(verhoeffValid("236121645073")).toBe(true);
    expect(verhoeffValid("236121645078")).toBe(false);
    expect(findNationalIds("ssn 123-45-6789").length).toBe(1);
    expect(findNationalIds("id 000-12-3456").length).toBe(0);
  });
});

describe("unicode", () => {
  it("flags zero-width and bidi", () => {
    expect(invisibleCharacters("ab​cd").length).toBe(1);
    expect(invisibleCharacters("a‮cd").length).toBe(1);
    expect(invisibleCharacters("tag󠅁").length).toBe(1);
  });
  it("allows emoji ZWJ sequences", () => expect(invisibleCharacters("\u{1f468}‍\u{1f469}")).toEqual([]));
  it("strips invisibles", () => expect(stripInvisible("a​b")).toBe("ab"));
  it("flags the BMP variation selectors, Hangul fillers, the braille blank and the grapheme joiner", () => {
    for (const c of ["\uFE00", "\uFE0F", "\u3164", "\u115F", "\u1160", "\uFFA0", "\u2800", "\u034F"]) {
      expect(invisibleCharacters(`rm${c}-rf`).length, c).toBe(1);
      expect(stripInvisible(`rm${c}-rf`), c).toBe("rm-rf");
    }
  });
  it("allows an emoji's presentation selector, a keycap and an ideograph variant", () => {
    expect(invisibleCharacters("\u2764\uFE0F ok")).toEqual([]);
    expect(invisibleCharacters("1\uFE0F\u20E3")).toEqual([]);
    expect(invisibleCharacters("\u2764\uFE0F\u200D\u{1F525}")).toEqual([]);
    expect(invisibleCharacters("\u845B\u{E0100}")).toEqual([]);
    expect(invisibleCharacters("\u2764\uFE0F\uFE0F")).toEqual(["variation selector"]);
  });
  it("allows only RGI subdivision flags, not any tag run after a black flag", () => {
    const flag = (letters: string) => `\u{1F3F4}${Array.from(letters, (c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("")}\u{E007F}`;
    expect(invisibleCharacters(`wales ${flag("gbwls")}`)).toEqual([]);
    expect(invisibleCharacters(`x ${flag("curl evil")}`)).toEqual(["Unicode tag characters"]);
  });
});

describe("sql", () => {
  it("classifies reads, writes, destroys", () => {
    expect(classifySql("select * from t").reads).toBe(true);
    expect(classifySql("insert into t values (1)").writes).toBe(true);
    expect(classifySql("drop table t").destroys).toBe(true);
    expect(classifySql("delete from t").destroys).toBe(true);
    expect(classifySql("delete from t where id=1").destroys).toBe(false);
  });
  it("sees a destructive statement hidden in a comment or after a read", () => {
    expect(classifySql("select 1; /* x */ drop table t").destroys).toBe(true);
    expect(classifySql("select '; drop table t'").destroys).toBe(false);
  });
  it("flags statements that reach outside the database", () => {
    expect(classifySql("copy t to program 'curl x'").external).toBe(true);
    expect(classifySql("select net.http_get('http://x')").external).toBe(true);
  });
  it("a MySQL # comment counts only at a line's start, read in linear time (regex-timing seed 26714)", () => {
    expect(classifySql("select 1;\n# drop table t").destroys).toBe(false);
    expect(classifySql("select 1;\n  # drop table t").destroys).toBe(false);
    expect(classifySql("select 1 # x;\ndrop table t").destroys).toBe(true);
    expect(classifySql("select '#';\ndrop table t").destroys).toBe(true);
    const t = (s: string): number => {
      const t0 = performance.now();
      classifySql(s);
      return performance.now() - t0;
    };
    // Output built by += was indexed at every "#": quadratic (15 ms at 80k characters, 183 ms at 160k).
    for (const unit of ["a&#COPY \u2066", "a-sk-&#.", "&# github.com/-"]) expect(t(unit.repeat(Math.ceil(320_000 / unit.length)))).toBeLessThan(150);
  });
});

describe("effects", () => {
  it("merging equal effects keeps every distinct download path, not only the first", () => {
    const c = newCollector(ctx(), defaultConfig(), emptyState());
    const base = { cls: "write_workspace" as const, target: "/w/x", detail: "save downloads under /w/x" };
    addEffect(c, { ...base, download: "/w/x/a" });
    addEffect(c, { ...base, download: "/w/x/b" });
    addEffect(c, { ...base, download: "/w/x/a" });
    expect(c.effects).toHaveLength(1);
    expect(downloadsOf(c.effects[0] as Effect)).toEqual(["/w/x/a", "/w/x/b"]);
  });
});

describe("network refusals", () => {
  it("a request a sandbox middleware refused is a deny under FW-NET-REFUSED, with its code and reason", () => {
    for (const state of [emptyState(), foldEvents([{ type: "taint", source: "x" }])]) {
      const d = decide({ action: { tool: NETWORK_REFUSED_TOOL, input: { url: "https://api.partner.example/x", method: "GET", code: "launchsafe_deny_host_mismatch", reason: "the Host header names evil.example, not the target" } }, state, config: defaultConfig(), ctx: ctx() });
      expect(d.verdict).toBe("deny");
      expect(d.rules).toContain("FW-NET-REFUSED");
      expect(d.reasons.join(" ")).toContain("evil.example");
      expect(d.reasons.join(" ")).toContain("launchsafe_deny_host_mismatch");
    }
  });
});
