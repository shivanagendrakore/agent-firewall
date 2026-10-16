/**
 * The typosquat check and the package-spec parsing it relies on.
 * Pure functions; the false-positive half runs every shipped popular name and
 * the friction corpus's installs through it.
 */

import { describe, expect, it } from "vitest";
import { ALWAYS_FINE, PACKAGES_FINE, TRUSTED_ONLY } from "../src/corpus.js";
import { POPULAR } from "../src/data/popular.js";
import { classifyAction } from "../src/engine/classify.js";
import { compareVersions, judge, normalizeName, notedPackages, parseNpmSpec, parsePep508, type Ecosystem } from "../src/engine/packages.js";
import { editDistance, typosquatOf } from "../src/engine/typosquat.js";
import { defaultConfig } from "../src/policy.js";
import { bash, ctx, explain, state } from "./helpers.js";

describe("edit distance (optimal string alignment)", () => {
  it("counts substitutions, insertions, deletions and adjacent transpositions as one", () => {
    expect(editDistance("react", "reacct", 2)).toBe(1);
    expect(editDistance("requests", "reqeusts", 2)).toBe(1);
    expect(editDistance("lodash", "lodas", 2)).toBe(1);
    expect(editDistance("express", "exprezz", 3)).toBe(2);
    expect(editDistance("same", "same", 1)).toBe(0);
  });
  it("stops early beyond the limit", () => {
    expect(editDistance("react", "angular", 1)).toBe(2);
    expect(editDistance("a", "abcdef", 1)).toBe(2);
  });
});

describe("typosquatOf: look-alikes are flagged", () => {
  const cases: [Ecosystem, string, string][] = [
    ["npm", "reacct", "react"],
    ["npm", "lodahs", "lodash"],
    ["npm", "expres", "express"],
    ["npm", "lodash-merge", "lodash.merge"],
    ["npm", "types-node", "@types/node"],
    ["npm", "@types/nodee", "@types/node"],
    ["npm", "mongose", "mongoose"],
    ["npm", "axois", "axios"],
    ["npm", "c0mmander", "commander"],
    ["npm", "express-js", "express"],
    ["npm", "node-axios", "axios"],
    ["npm", "typescirpt", "typescript"],
    ["npm", "tpyescrpit", "typescript"],
    ["PyPI", "reqeusts", "requests"],
    ["PyPI", "python-requests", "requests"],
    ["PyPI", "requests-py", "requests"],
    ["PyPI", "beautifulsoupp", "beautifulsoup4"],
    ["PyPI", "djang0", "django"],
    ["PyPI", "matplotllib", "matplotlib"],
    ["crates.io", "serde-jsonn", "serde_json"],
    ["crates.io", "tokioo", "tokio"],
    ["RubyGems", "nokogirl", "nokogiri"],
    ["RubyGems", "rails-ruby", "rails"],
  ];
  for (const [eco, name, target] of cases) {
    it(`${eco} ${name} -> ${target}`, () => {
      const t = typosquatOf(eco, name);
      expect(t, `${name} not flagged`).not.toBeNull();
      expect(normalizeName(eco, t?.lookalike ?? "")).toBe(normalizeName(eco, target));
    });
  }
});

describe("typosquatOf: no false positives", () => {
  it("never flags a shipped target or known name", () => {
    for (const [eco, list] of Object.entries(POPULAR) as [Ecosystem, NonNullable<(typeof POPULAR)[Ecosystem]>][]) {
      for (const n of [...list.targets, ...list.known]) expect(typosquatOf(eco, n), `${eco} ${n}`).toBeNull();
    }
  });
  it("spec FP2: preact is a target, not a typo of react", () => expect(typosquatOf("npm", "preact")).toBeNull());
  it("short names are not compared by edit distance", () => {
    for (const n of ["zod", "ms", "qs", "pg", "ws", "vue", "got", "nx", "joi", "yup"]) expect(typosquatOf("npm", n), n).toBeNull();
  });
  it("unrelated names and ecosystems without lists are not flagged", () => {
    expect(typosquatOf("npm", "my-company-internal-utils")).toBeNull();
    expect(typosquatOf("Go", "github.com/x/reacct")).toBeNull();
    expect(typosquatOf("Maven", "org.example:lib")).toBeNull();
  });
  it("PyPI names are compared after PEP 503 normalisation (Django, PyYAML, scikit_learn)", () => {
    for (const n of ["Django", "PyYAML", "scikit_learn", "Jinja2", "typing_extensions"]) expect(typosquatOf("PyPI", n), n).toBeNull();
  });
  it("the friction corpus's install commands stay allowed, trusted", () => {
    for (const c of [...ALWAYS_FINE, ...TRUSTED_ONLY]) {
      const d = bash(c);
      expect(d.rules, `${c}: ${explain(d)}`).not.toContain("FW-TYPOSQUAT");
    }
  });
  it("every list records its source and date", () => {
    for (const list of Object.values(POPULAR)) {
      expect(list?.source).toMatch(/\S/);
      expect(list?.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
});

describe("package spec parsing", () => {
  it("npm specs", () => {
    expect(parseNpmSpec("evil@1.0.0")).toEqual({ name: "evil", version: "1.0.0", range: null });
    expect(parseNpmSpec("@scope/pkg@2.1.0-beta.1")).toEqual({ name: "@scope/pkg", version: "2.1.0-beta.1", range: null });
    expect(parseNpmSpec("next@15")).toEqual({ name: "next", version: null, range: "15" });
    expect(parseNpmSpec("react@^18")).toEqual({ name: "react", version: null, range: "^18" });
    expect(parseNpmSpec("react@latest")).toEqual({ name: "react", version: null, range: null });
    expect(parseNpmSpec("@types/node")).toEqual({ name: "@types/node", version: null, range: null });
    expect(parseNpmSpec("alias@npm:real@1.2.3")).toEqual({ name: "real", version: "1.2.3", range: null });
    for (const x of ["./local", "/abs/path", "~/x", "github:user/repo", "user/repo", "git+https://x/y.git", "https://x.example/p.tgz", "file:../x", "pkg@file:../x", "pkg.tgz"]) expect(parseNpmSpec(x), x).toBeNull();
  });
  it("PEP 508 requirements", () => {
    expect(parsePep508("requests==2.32.3")).toEqual({ name: "requests", version: "2.32.3", range: null });
    expect(parsePep508("Evil_Fixture[extra]==1.0; python_version>'3.8'")).toEqual({ name: "Evil_Fixture", version: "1.0", range: null });
    expect(parsePep508("flask>=3")).toEqual({ name: "flask", version: null, range: ">=3" });
    expect(parsePep508("pkg==1.*")).toEqual({ name: "pkg", version: null, range: "==1.*" });
    expect(parsePep508("tool@1.2.0")).toEqual({ name: "tool", version: "1.2.0", range: null });
    for (const x of ["./pkg", "pkg @ https://x/y.whl", "git+https://x/y", "dist/pkg-1.0.whl"]) expect(parsePep508(x), x).toBeNull();
  });
  it("what each manager's command asks for", () => {
    const asks = (command: string): string[] => {
      const c = classifyAction({ tool: "Bash", input: { command } }, ctx(), defaultConfig(), state());
      const n = notedPackages(c);
      return [...n.requests.map((r) => `${r.eco}:${r.name}@${r.version ?? r.range ?? ""}`), ...n.lockfiles.map((l) => `lock:${l.eco}${l.files.length > 0 ? `:${l.files.map((f) => f.split("/").pop()).join(",")}` : ""}`)];
    };
    expect(asks("npm install react@18.3.1 -D")).toEqual(["npm:react@18.3.1"]);
    expect(asks("npm -w web install zod")).toEqual(["npm:zod@"]);
    expect(asks("pnpm --filter web add zod")).toEqual(["npm:zod@"]);
    expect(asks("npm ci")).toEqual(["lock:npm"]);
    expect(asks("npm install")).toEqual(["lock:npm"]);
    expect(asks("yarn")).toEqual(["lock:npm"]);
    expect(asks("npm init vite@5")).toEqual(["npm:create-vite@5"]);
    expect(asks("yarn create @scope/app")).toEqual(["npm:@scope/create-app@"]);
    expect(asks("pip install -r requirements.txt")).toEqual(["lock:PyPI:requirements.txt"]);
    expect(asks("pip install 'flask>=3' requests==2.0.0")).toEqual(["PyPI:flask@>=3", "PyPI:requests@2.0.0"]);
    expect(asks("uv sync")).toEqual(["lock:PyPI"]);
    expect(asks("uv tool install ruff")).toEqual(["PyPI:ruff@"]);
    expect(asks("uvx --from black==24.1.0 black .")).toEqual(["PyPI:black@24.1.0"]);
    expect(asks("poetry install")).toEqual(["lock:PyPI"]);
    expect(asks("cargo add serde@1.0.200")).toEqual(["crates.io:serde@1.0.200"]);
    expect(asks("cargo install ripgrep --version 14.1.0")).toEqual(["crates.io:ripgrep@14.1.0"]);
    expect(asks("cargo build --release")).toEqual(["lock:crates.io"]);
    expect(asks("gem install rails -v 7.1.0")).toEqual(["RubyGems:rails@7.1.0"]);
    expect(asks("bundle install")).toEqual(["lock:RubyGems"]);
    expect(asks("go install golang.org/x/tools/gopls@v0.16.0")).toEqual(["Go:golang.org/x/tools/gopls@v0.16.0"]);
    expect(asks("go run ./cmd/server")).toEqual([]);
    expect(asks("composer require monolog/monolog:3.5.0")).toEqual(["Packagist:monolog/monolog@3.5.0"]);
    expect(asks("composer install")).toEqual(["lock:Packagist"]);
    expect(asks("npm test")).toEqual([]);
    expect(asks("pnpm exec vitest run")).toEqual([]);
  });
});

describe("version judgement", () => {
  const entry = { all: false, versions: ["1.0.0"], ranges: [{ introduced: "2.0.0", fixed: "2.1.0" }, { introduced: "3.0.0", last_affected: "3.0.5" }], ids: ["MAL-X"] };
  it("listed, in a range, outside, and no version", () => {
    expect(judge("npm", entry, "1.0.0")).toBe("malicious");
    expect(judge("npm", entry, "2.0.7")).toBe("malicious");
    expect(judge("npm", entry, "2.1.0")).toBe("clean");
    expect(judge("npm", entry, "3.0.5")).toBe("malicious");
    expect(judge("npm", entry, "3.0.6")).toBe("clean");
    expect(judge("npm", entry, null)).toBe("maybe");
    expect(judge("npm", { ...entry, all: true }, "9.9.9")).toBe("malicious");
  });
  it("a version the comparator cannot read is 'maybe', never 'clean'", () => {
    expect(judge("npm", { all: false, versions: [], ranges: [{ introduced: "1.0.0" }], ids: [] }, "not-a-version")).toBe("maybe");
  });
  it("compares numeric segments and pre-releases", () => {
    expect(compareVersions("1.10.0", "1.9.0")).toBeGreaterThan(0);
    expect(compareVersions("v2.0.0", "2.0.0")).toBe(0);
    expect(compareVersions("1.0.0-rc.1", "1.0.0")).toBeLessThan(0);
    expect(compareVersions("1.0", "1.0.0")).toBe(0);
    expect(() => compareVersions("abc", "1.0")).toThrow();
  });
});

describe("R16: widely used packages are not typosquats", () => {
  it.each([["npm", PACKAGES_FINE.npm], ["PyPI", PACKAGES_FINE.PyPI]] as const)("%s corpus: none is flagged", (eco, list) => {
    expect(list.filter((n) => typosquatOf(eco, n) !== null)).toEqual([]);
  });
  it("a look-alike of a real package is still flagged", () => {
    expect(typosquatOf("npm", "reacts")).not.toBeNull();
    expect(typosquatOf("npm", "validator.js")).not.toBeNull();
  });
});
