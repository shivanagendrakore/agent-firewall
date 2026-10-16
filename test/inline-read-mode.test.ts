/**
 * F-b: inline code that can only read is judged as a reader of the paths it names; code that can write,
 * run programs, reach the network or reflect is judged as in v0.1. Acceptance rows B1-B17, FP1-FP8.
 * {H} = /Users/dev, {W} = /Users/dev/proj.
 */
import { describe, expect, it } from "vitest";
import { capabilities, isReadOnly, langOf } from "../src/engine/shell/inline.js";
import { bash, explain } from "./helpers.js";

const H = "/Users/dev";
const W = "/Users/dev/proj";
const dl = { type: "downloaded" as const, path: `${W}/scripts/x.js` };

describe("F-b acceptance", () => {
  it("B1/B2: python json.load of ~/.claude/settings.json is allowed, trusted and untrusted", () => {
    const cmd = `python3 -c "import json;print(json.load(open('${H}/.claude/settings.json'))['hooks'])"`;
    for (const tainted of [false, true]) {
      const d = bash(cmd, { tainted });
      expect(d.verdict, explain(d)).toBe("allow");
    }
  });
  it("B3: reading then writing settings is FW-TAMPER", () => {
    const d = bash(`python3 -c "import json;d=json.load(open('${H}/.claude/settings.json'));open('${H}/.claude/settings.json','w').write('{}')"`);
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-TAMPER");
  });
  it("B4: pathlib read_text of CLAUDE.md is allowed", () => {
    const d = bash(`python3 -c "import pathlib;print(pathlib.Path('${W}/CLAUDE.md').read_text())"`);
    expect(d.verdict, explain(d)).toBe("allow");
  });
  it("B5: pathlib write_text of CLAUDE.md (untrusted) is held", () => {
    const d = bash(`python3 -c "import pathlib;pathlib.Path('${W}/CLAUDE.md').write_text('x')"`, { tainted: true });
    expect(d.verdict, explain(d)).toBe("queue");
    expect(d.rules).toContain("FW-INSTRUCTIONS-HELD");
  });
  it("B6: node readFileSync of .mcp.json is allowed", () => {
    const d = bash(`node -e "console.log(JSON.parse(require('fs').readFileSync('${W}/.mcp.json','utf8')))"`);
    expect(d.verdict, explain(d)).toBe("allow");
  });
  it("B7: node writeFileSync of .mcp.json asks FW-AGENT-SETTINGS", () => {
    const d = bash(`node -e "require('fs').writeFileSync('${W}/.mcp.json','{}')"`);
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-AGENT-SETTINGS");
  });
  it("B8: ruby JSON.parse(File.read(settings)) is allowed", () => {
    const d = bash(`ruby -rjson -e "puts JSON.parse(File.read('${H}/.claude/settings.json'))"`);
    expect(d.verdict, explain(d)).toBe("allow");
  });
  it("B9: perl three-argument read open of AGENTS.md is allowed", () => {
    const d = bash(`perl -e 'open(my $f,"<","${W}/AGENTS.md"); print <$f>'`);
    expect(d.verdict, explain(d)).toBe("allow");
  });
  it("B10: perl write open of AGENTS.md (untrusted) is held", () => {
    const d = bash(`perl -e 'open(my $f,">","${W}/AGENTS.md")'`, { tainted: true });
    expect(d.verdict, explain(d)).toBe("queue");
    expect(d.rules).toContain("FW-INSTRUCTIONS-HELD");
  });
  it("B11: getattr-built open is dynamic, so the write probe applies (held)", () => {
    const d = bash(`python3 -c "getattr(__builtins__,'op'+'en')('${W}/CLAUDE.md','w')"`, { tainted: true });
    expect(d.verdict, explain(d)).toBe("queue");
    expect(d.rules).toContain("FW-INSTRUCTIONS-HELD");
  });
  it("B12: code that imports subprocess and names settings is FW-TAMPER (unchanged from v0.1)", () => {
    const d = bash(`python3 -c "import subprocess;print(open('${H}/.claude/settings.json').read())"`);
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-TAMPER");
  });
  it("B13: a read of ~/.aws/credentials asks FW-CREDENTIAL-READ", () => {
    const d = bash(`python3 -c "print(open('${H}/.aws/credentials').read())"`);
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-CREDENTIAL-READ");
  });
  it("B14: a here-document that json.loads .claude/settings.json is allowed", () => {
    const d = bash("python3 - <<'EOF'\nimport json\nprint(json.load(open('.claude/settings.json')))\nEOF");
    expect(d.verdict, explain(d)).toBe("allow");
  });
  it("B15: node require of a downloaded file (untrusted) is FW-UNTRUSTED-CODE", () => {
    const d = bash(`node -e "require('${W}/scripts/x.js')"`, { tainted: true, events: [dl] });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-UNTRUSTED-CODE");
  });
  it("B16: osascript stays 'other' and gets the v0.1 write probe", () => {
    expect(langOf("osascript")).toBe("other");
    const d = bash(`osascript -e 'read POSIX file "${W}/CLAUDE.md"'`, { tainted: true });
    expect(d.effects.some((e) => e.cls === "write_protected"), explain(d)).toBe(true);
  });
  it("B17: a write to a computed path in an untrusted session asks FW-UNCLASSIFIABLE (F5, unchanged)", () => {
    const d = bash(`python3 -c "import os;open(os.path.join(os.environ['HOME'],'.zshrc'),'a')"`, { tainted: true });
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-UNCLASSIFIABLE");
  });
});

describe("F-b false positives (allowed, trusted and untrusted)", () => {
  for (const cmd of [
    `python3 -c "import json,sys;print(json.load(open('package.json'))['version'])"`,
    `python3 -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project'])"`,
    `node -p "require('./package.json').scripts"`,
    `node -e "console.log(Object.keys(JSON.parse(require('fs').readFileSync('.claude/settings.json','utf8'))))"`,
    `ruby -ryaml -e "p YAML.load_file('.github/workflows/ci.yml').keys"`,
    `python3 -c "import yaml;print(yaml.safe_load(open('.pre-commit-config.yaml')))"`,
    `php -r 'var_dump(json_decode(file_get_contents("composer.json")));'`,
    `python3 -c "import os;print(os.path.exists('${H}/.claude/settings.json'))"`,
  ]) {
    it(cmd, () => {
      for (const tainted of [false, true]) {
        const d = bash(cmd, { tainted });
        expect(d.verdict, `${tainted ? "untrusted" : "trusted"}: ${explain(d)}`).toBe("allow");
      }
    });
  }
});

describe("capabilities by language", () => {
  const ro = (lang: Parameters<typeof capabilities>[0], code: string): boolean => isReadOnly(lang, capabilities(lang, code));
  it("python modes and APIs", () => {
    expect(ro("python", "print(open('a').read())")).toBe(true);
    expect(ro("python", "print(open('a', 'rb').read())")).toBe(true);
    expect(ro("python", "open('a', mode='w')")).toBe(false);
    expect(ro("python", "open('a', m)")).toBe(false);
    expect(ro("python", "import shutil;shutil.rmtree('x')")).toBe(false);
    expect(ro("python", "import shutil;print(shutil.which('git'))")).toBe(true);
    expect(ro("python", "import requests")).toBe(false);
    expect(ro("python", "import json;json.dump({}, open('x','w'))")).toBe(false);
    expect(ro("python", "import mymodule")).toBe(false);
  });
  it("node, ruby, perl, php, deno, bun", () => {
    expect(ro("node", "console.log(require('fs').existsSync('a'))")).toBe(true);
    expect(ro("node", "require('fs').rmSync('a')")).toBe(false);
    expect(ro("node", "require('child_process').execSync('ls')")).toBe(false);
    expect(ro("node", "require(name)")).toBe(false);
    expect(ro("node", "require('left-pad')")).toBe(false);
    expect(ro("node", "process.stdout.write(require('fs').readFileSync('a','utf8'))")).toBe(true);
    expect(ro("ruby", "puts File.read('a')")).toBe(true);
    expect(ro("ruby", "File.open('a', 'w') {}")).toBe(false);
    expect(ro("ruby", "puts `ls`")).toBe(false);
    expect(ro("perl", 'open(my $f, ">>", "a")')).toBe(false);
    expect(ro("perl", 'unlink "a"')).toBe(false);
    expect(ro("php", 'echo file_get_contents("a");')).toBe(true);
    expect(ro("php", 'file_put_contents("a", "x");')).toBe(false);
    expect(ro("php", 'fopen("a", "w");')).toBe(false);
    expect(ro("deno", "console.log(await Deno.readTextFile('a'))")).toBe(true);
    expect(ro("deno", "await Deno.writeTextFile('a','x')")).toBe(false);
    expect(ro("bun", "console.log(await Bun.file('a').text())")).toBe(true);
    expect(ro("bun", "await Bun.write('a','x')")).toBe(false);
    expect(ro("other", "anything")).toBe(false);
  });
  it("network and reflection are never read-only", () => {
    expect(ro("python", "import urllib.request;print(open('a').read())")).toBe(false);
    expect(ro("node", "fetch('https://x')")).toBe(false);
    expect(ro("node", "globalThis['req'+'uire']('fs')")).toBe(false);
    expect(ro("ruby", "File.send(:wri.to_s + 'te', 'a', 'x')")).toBe(false);
    expect(ro("python", "import base64;print(base64.b64decode('eA=='))")).toBe(false);
  });
});
