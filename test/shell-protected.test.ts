/**
 * The known weakness of hook-based tools: a protected file (agent
 * instructions, memory, settings, hooks, the firewall's own files) changed
 * through the shell instead of the Edit/Write tools. The property under test:
 * every shell form that writes a protected path is CLASSIFIED as a protected
 * write (so an untrusted session holds it for review, exactly like the Write
 * tool), and firewall files are denied outright. Anything the parser cannot
 * resolve falls to the strict class.
 */
import { describe, expect, it } from "vitest";
import { classifyAction } from "../src/engine/classify.js";
import { defaultConfig } from "../src/policy.js";
import { emptyState } from "../src/engine/state.js";
import { bash, ctx, explain } from "./helpers.js";

const WS = "/Users/dev/proj";
function effects(cmd: string): string[] {
  return classifyAction({ tool: "Bash", input: { command: cmd } }, ctx(), defaultConfig(), emptyState()).effects.map((e) => e.cls);
}

describe("shell writes to instruction/memory files are classified protected and held when untrusted", () => {
  const cmds: string[] = [
    `echo 'x' > ${WS}/CLAUDE.md`,
    `echo 'x' >> CLAUDE.md`,
    `printf 'x' > ./AGENTS.md`,
    `cat evil.txt > ${WS}/CLAUDE.md`,
    `tee CLAUDE.md < evil.txt`,
    `tee -a AGENTS.md <<< 'content'`,
    `cp evil.md CLAUDE.md`,
    `mv evil.md AGENTS.md`,
    `sed -i 's/a/b/' CLAUDE.md`,
    `sed -i.bak 's/a/b/' AGENTS.md`,
    `perl -i -pe 's/a/b/' CLAUDE.md`,
    `dd if=evil of=CLAUDE.md`,
    `install -m 644 evil.md CLAUDE.md`,
    `cat > .cursorrules <<'EOF2'\nrules\nEOF2`,
    `python3 -c "open('CLAUDE.md','w').write('x')"`,
    `node -e "require('fs').writeFileSync('CLAUDE.md','x')"`,
    `truncate -s 0 AGENTS.md`,
    `: > CLAUDE.md`,
    `echo x | tee CLAUDE.md`,
    `rsync evil.md CLAUDE.md`,
    `git checkout other -- CLAUDE.md`,
    `ln -sf /etc/passwd ${WS}/CLAUDE.md`,
  ];
  for (const cmd of cmds) {
    it(cmd.replace(/\n/g, " ").slice(0, 55), () => {
      expect(effects(cmd), `classified: ${effects(cmd).join(",")}`).toContain("write_protected");
      const u = bash(cmd, { tainted: true });
      expect(["queue", "ask", "deny"], `untrusted: ${explain(u)}`).toContain(u.verdict);
    });
  }
});

describe("shell writes to settings/hooks need a person even when trusted", () => {
  for (const cmd of [`echo x > ${WS}/.claude/settings.json`, `cp evil ${WS}/.mcp.json`, `echo x > .claude/hooks/pre.sh`, `tee ${WS}/.cursor/mcp.json < evil`]) {
    it(cmd.slice(0, 50), () => {
      const d = bash(cmd);
      expect(["ask", "queue", "deny"], explain(d)).toContain(d.verdict);
    });
  }
});

describe("shell writes to the firewall's own files are denied", () => {
  const home = "/Users/dev/.launchsafe-firewall";
  for (const cmd of [`echo x > ${home}/policy.json`, `rm -rf ${home}`, `cp evil.json ${home}/policy.json`, `sed -i 's/a/b/' ${home}/policy.json`, `tee ${home}/policy.json < evil`, `launchsafe-firewall uninstall`, `pkill -f launchsafe-firewall`]) {
    it(cmd.slice(0, 50), () => {
      const d = bash(cmd);
      expect(d.verdict, explain(d)).toBe("deny");
      expect(d.rules).toContain("FW-TAMPER");
    });
  }
});

describe("persistence files need a person once untrusted", () => {
  for (const cmd of [`echo 'x' > ${WS}/.git/hooks/pre-commit`, `echo 'x' >> ~/.bashrc`, `cp evil ~/.zshrc`, `echo x > ${WS}/.github/workflows/ci.yml`]) {
    it(cmd.slice(0, 50), () => {
      const d = bash(cmd, { tainted: true });
      expect(["ask", "queue", "deny"], explain(d)).toContain(d.verdict);
    });
  }
});

describe("unresolvable shell writes fall to the strict class", () => {
  for (const cmd of [`echo x > "$TARGET"`, `cp evil "$DEST"`, `eval "echo x > $F"`, `bash -c "$CMD"`, `mv x $(cat location.txt)`]) {
    it(cmd.slice(0, 40), () => {
      const d = bash(cmd);
      expect(["ask", "queue", "deny"], explain(d)).toContain(d.verdict);
    });
  }
});

describe("F-a: the firewall's own CLI, read-only list derived from its command specs", () => {
  it("A17: install --help is allowed (help has no side effects)", () => {
    const d = bash("launchsafe-firewall install --help");
    expect(d.verdict, explain(d)).toBe("allow");
  });
  it("A18: install is tampering", () => {
    const d = bash("launchsafe-firewall install");
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-TAMPER");
  });
  it("A19: doctor --fix is tampering", () => {
    const d = bash("launchsafe-firewall doctor --fix");
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).toContain("FW-TAMPER");
  });
  it("A20: node <install>/dist/cli.js queue approve q1 -h is help only", () => {
    const d = bash("node /opt/launchsafe-firewall/dist/cli.js queue approve q1 -h", { tainted: true });
    expect(d.verdict, explain(d)).toBe("allow");
  });
  it("FP4 / SELF-012: status, queue list, log verify, explain are allowed", () => {
    for (const c of ["launchsafe-firewall status", "launchsafe-firewall queue list", "launchsafe-firewall log verify", "launchsafe-firewall doctor", "launchsafe-firewall explain FW-SEND"]) {
      const d = bash(c, { tainted: true });
      expect(d.verdict, `${c}: ${explain(d)}`).toBe("allow");
    }
  });
  it("a computed argument is not read-only", () => {
    const d = bash('launchsafe-firewall queue $SUB "$ID"');
    expect(d.verdict, explain(d)).toBe("deny");
  });
});
