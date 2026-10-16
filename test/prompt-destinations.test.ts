import { describe, expect, it } from "vitest";
import { destinationsFromPrompt } from "../src/engine/post.js";

const d = (p: string): string[] => destinationsFromPrompt(p).sort();

describe("destinationsFromPrompt", () => {
  it("a URL contributes only its host (the reported case)", () => {
    expect(d("read https://named.example.com/guide please")).toEqual(["named.example.com"]);
  });

  it.each([
    ["https://example.com/a/b/c", ["example.com"]],
    ["see (https://example.com/docs/intro.html), then stop", ["example.com"]],
    ["https://example.com:8443/owner/repo?x=1#frag", ["example.com"]],
    ["http://user:pw@example.org/acme/app", ["example.org"]],
    ["https://github.com.evil.example/acme/app", ["github.com.evil.example"]],
  ])("URL with a path: %s", (p, want) => {
    expect(d(p)).toEqual(want);
  });

  it("owner/repo alone, and in prose", () => {
    expect(d("acme/app")).toEqual(["github:acme/app"]);
    expect(d("please push to Acme/App-Server.")).toEqual(["github:acme/app-server"]);
    expect(d("clone acme/app.git, then build")).toEqual(["github:acme/app"]);
    expect(d("(acme/app) and \"octo-cat/hello.world\"")).toEqual(["github:acme/app", "github:octo-cat/hello.world"]);
  });

  it("github.com URLs give that repository", () => {
    expect(d("https://github.com/acme/app")).toEqual(["github.com", "github:acme/app"]);
    expect(d("https://github.com/acme/app/pull/12")).toEqual(["github.com", "github:acme/app"]);
    expect(d("https://github.com/acme/app.git.")).toEqual(["github.com", "github:acme/app"]);
    expect(d("github.com/acme/app")).toEqual(["github.com", "github:acme/app"]);
    expect(d("git@github.com:acme/app.git")).toEqual(["github:acme/app"]);
    expect(d("https://github.com/orgs/acme/people")).toEqual(["github.com"]);
    expect(d("https://github.com/acme")).toEqual(["github.com"]);
  });

  it("emails name a mailbox, not a host or a repository", () => {
    expect(d("mail dev@example.com about it")).toEqual([]);
    expect(d("a/b@example.com")).toEqual([]);
    expect(d("cc first.last+tag@mail.example.co.uk.")).toEqual([]);
  });

  it("a bare host is kept, with trailing punctuation dropped", () => {
    expect(d("go to example.com.")).toEqual(["example.com"]);
    expect(d("try api.example.com, or docs.example.org!")).toEqual(["api.example.com", "docs.example.org"]);
    expect(d("example.com/owner/repo")).toEqual(["example.com"]);
  });

  it.each([
    "src/app", "docs/readme.md", "src/index.ts", "and/or", "yes/no", "I/O", "TCP/IP", "24/7", "10/11/2026",
    "a/b/c", "foo/bar/baz", "./acme/app", "../acme/app", "/acme/app", "~/acme/app", "C:/acme/app", "x:acme/app",
    "-acme/app", "acme-/app", "ac--me/app", "acme/..", "acme/.", "node_modules/pkg", "lib/util.js", "owner/1234",
    "https://", "user@host", "version 1.2.3 and v2.0", "e.g. and i.e.", "README.md and notes.txt", "config.json",
    "foo.example", "not-a-url.", "a.b", "1.2.3.4x", "see:acme/app", "acme/app/", "acme/app/more", "pre-acme/app/x",
    "x".repeat(40) + "/repo", "acme/" + "r".repeat(101),
  ])("near-miss gives nothing extra: %s", (p) => {
    const got = d(p).filter((x) => x.startsWith("github:"));
    expect(got).toEqual([]);
  });

  it("near-misses with hosts give no host either", () => {
    for (const p of ["README.md", "a/b.ts", "user@example.com", "foo@bar.baz.com", "e.g.", "v1.2.3", "package.json"]) expect(d(p)).toEqual([]);
  });
});
