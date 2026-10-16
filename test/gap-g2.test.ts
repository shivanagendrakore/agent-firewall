/**
 * Gap G2: a runner invoked by path checks the manifest.
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


describe("G2: a runner invoked by path checks the manifest", () => {
  it("./gradlew after build.gradle.kts changed asks", () => {
    asks("./gradlew build", "FW-TAINTED-MANIFEST", written("build.gradle.kts"));
    asks("./mvnw test", "FW-TAINTED-MANIFEST", written("pom.xml"));
    asks("./node_modules/.bin/vitest run", "FW-TAINTED-MANIFEST", written("vitest.config.ts"));
    asks("bin/rails test", "FW-TAINTED-MANIFEST", written("Gemfile"));
  });
  it("is allowed when nothing changed, trusted or not", () => {
    for (const c of ["./gradlew build", "./mvnw test", "./node_modules/.bin/vitest run", "bin/rails test", "./scripts/deploy-docs.sh"]) {
      allows(c);
      allows(c, {});
    }
  });
  it("an unrelated file change does not ask", () => allows("./gradlew build", written("src/App.kt")));
});
