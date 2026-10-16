/**
 * Gap G3: deploy tools are modelled.
 */
import { describe, expect, it } from "vitest";
import { bash, explain, WS, type RunOpts } from "./helpers.js";

const UNTRUSTED: RunOpts = { tainted: true };
const written = (...p: string[]): RunOpts => ({ tainted: true, events: p.map((x) => ({ type: "tainted_write" as const, path: `${WS}/${x}` })) });
const allows = (c: string, o: RunOpts = UNTRUSTED): void => expect(bash(c, o).verdict, explain(bash(c, o))).toBe("allow");
const asks = (c: string, rule: string, o: RunOpts): void => {
  const d = bash(c, o);
  expect(d.verdict, explain(d)).toBe("ask");
  expect(d.rules, explain(d)).toContain(rule);
};


describe("G3: deploy tools are modelled", () => {
  it("builds, lanes and submits are sends", () => {
    for (const c of ["fastlane beta", "fastlane ios release", "eas build --platform ios", "eas submit -p ios", "eas update --branch prod", "expo publish", "codemagic-cli-tools app-store-connect publish"]) {
      const d = bash(c, UNTRUSTED);
      expect(d.verdict, `${c}: ${explain(d)}`).toBe("ask");
      expect(d.rules).toContain("FW-SEND");
    }
  });
  it("deletes are destructive", () => {
    const d = bash("eas channel:delete preview", {});
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-DESTRUCTIVE");
  });
  it("lists, status and local development are not", () => {
    for (const c of ["fastlane lanes", "fastlane --version", "eas whoami", "eas build:list", "eas build --local --platform ios", "expo start", "expo export", "expo doctor"]) allows(c);
  });
  it("a sending tool is allowed in a trusted session, as other cloud CLIs are", () => allows("fastlane beta", {}));
  it("a lane runs the Fastfile, so a changed Fastfile asks first", () => asks("fastlane lanes", "FW-TAINTED-MANIFEST", written("fastlane/Fastfile")));
});
