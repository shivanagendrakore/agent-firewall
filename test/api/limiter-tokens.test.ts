/** The API's rate limiter under a clock that steps back, and the token file's ownership and mode. */

import { chmodSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { tokensPath } from "../../src/api/files.js";
import { DEFAULT_LIMITS, Limiter } from "../../src/api/server.js";
import { addToken, readTokens } from "../../src/api/tokens.js";
import { apiTree, removeApiTree, type ApiTree } from "./harness.js";

describe("the token bucket and a clock that steps backwards", () => {
  it("a backwards step takes no tokens away and refilling resumes from the new time", () => {
    let t = 1_000_000;
    const lim = new Limiter({ ...DEFAULT_LIMITS, perAgentPerSecond: 1, perAgentBurst: 2, perAgentConcurrent: 10 }, () => t);
    expect(lim.agent("a")).toBeNull();
    expect(lim.agent("a")).toBeNull();
    expect(lim.agent("a")).not.toBeNull(); // empty
    t -= 60_000; // the clock steps back a minute
    expect(lim.agent("a")).not.toBeNull(); // still empty, and not negative
    t += 1_000; // one second after the new time: one token
    expect(lim.agent("a")).toBeNull();
  });
});

describe.skipIf(process.platform === "win32")("the token file is trusted only when private", () => {
  let t: ApiTree;
  beforeEach(() => {
    t = apiTree();
  });
  afterEach(() => removeApiTree(t));

  it("reads a 0600 file, and refuses one that group or others can read", () => {
    addToken(t.l, "bot");
    expect(readTokens(t.l)).toHaveLength(1);
    chmodSync(tokensPath(t.l), 0o644);
    expect(() => readTokens(t.l)).toThrow(/no group or other access/);
    chmodSync(tokensPath(t.l), 0o600);
    expect(readTokens(t.l)).toHaveLength(1);
  });

  it("a missing file is an empty store", () => {
    expect(readTokens(t.l)).toEqual([]);
  });
});
