/**
 * Item 2: ps is run by absolute path (/bin/ps or /usr/bin/ps), never looked up through PATH, which an agent's
 * settings can point at a program of its own that ends the parent walk early. execFileSync is replaced here, so
 * nothing is run; the tests only look at what would have been.
 */
import { execFileSync } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import { processArgs, processLine } from "../src/runtime/ancestry.js";
import { processStart } from "../src/gateway/session.js";

vi.mock("node:child_process", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:child_process")>();
  return { ...real, execFileSync: vi.fn(() => "  1 /bin/zsh\n") };
});

describe("ps by absolute path", () => {
  it("processLine, processArgs and processStart run /bin/ps or /usr/bin/ps, never a ps found through PATH", () => {
    vi.mocked(execFileSync).mockClear();
    expect(processLine(50, { platform: "darwin" })).toBe("1 /bin/zsh");
    expect(processArgs(50, { platform: "darwin" })).toBe("1 /bin/zsh");
    expect(processStart(50, { platform: "darwin" })).toBe("1binzsh");
    const calls = vi.mocked(execFileSync).mock.calls;
    expect(calls.map((c) => c[1])).toEqual([
      ["-o", "ppid=,command=", "-p", "50"],
      ["-o", "args=", "-p", "50"],
      ["-o", "lstart=", "-p", "50"],
    ]);
    for (const c of calls) expect(c[0]).toMatch(/^\/(?:usr\/)?bin\/ps$/);
  });
});
