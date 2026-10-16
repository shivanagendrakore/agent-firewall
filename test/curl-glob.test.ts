/**
 * curl URL globbing ({a,b} and [x-y]) as the firewall reads it for the hosts a command contacts: every
 * alternative of a group is judged (no per-group limit), a range in the host asks, past the total limit it
 * asks, and an alternative is inserted as written ("$&" is not a replacement pattern).
 */

import { describe, expect, it } from "vitest";
import { bash, explain } from "./helpers.js";

const targets = (command: string): string[] => bash(command).effects.filter((e) => e.cls === "egress_fetch" || e.cls === "egress_send").map((e) => e.target);

describe("curl {a,b} globbing", () => {
  it("every alternative of a long group is judged, the 17th and later too", () => {
    const alts = [...Array.from({ length: 20 }, (_, i) => `a${i}`), "evil"].join(",");
    const d = bash(`curl 'https://{${alts}}.example.com/x'`);
    const t = d.effects.map((e) => e.target).join(" ");
    expect(t, explain(d)).toContain("evil.example.com");
    expect(t).toContain("a19.example.com");
  });

  it("an alternative is inserted as written: $& and $' are not replacement patterns", () => {
    const t = targets(`curl 'https://good.example.com/{a,$&,$'"'"'}'`).join(" ");
    expect(t).toContain("good.example.com/a");
    expect(t).toContain("good.example.com/$&");
    expect(t).not.toContain("{");
  });

  it("past the total limit the command asks (too_large) instead of judging only the first addresses", () => {
    const d = bash(`curl 'https://x.example.com/${"{a,b}".repeat(9)}'`);
    expect(d.findings.map((f) => f.id), explain(d)).toContain("too_large");
    expect(d.verdict).not.toBe("allow");
  });

  it("a [x-y] range in the host asks: only its first value could be judged", () => {
    const d = bash("curl 'https://h[1-9].example.com/x'");
    expect(d.findings.map((f) => f.id), explain(d)).toContain("unresolvable_command");
    expect(d.verdict).not.toBe("allow");
    // A range in the path does not change the host: no such finding.
    const p = bash("curl 'https://docs.example.com/page[1-9].html'");
    expect(p.findings.map((f) => f.id), explain(p)).not.toContain("unresolvable_command");
  });
});
