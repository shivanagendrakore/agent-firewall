import { describe, expect, it } from "vitest";
import { explanationFor } from "./blocked-view.js";
import { displayHost, displayUrlHost, hostToUnicode, mixesScripts, punycodeDecode } from "./host-display.js";
import { approvalTitle } from "./view.js";

describe("host display (m12)", () => {
  it("decodes Punycode labels (RFC 3492 samples and a look-alike)", () => {
    expect(punycodeDecode("pple-43d")).toBe("аpple");
    expect(punycodeDecode("mnchen-3ya")).toBe("münchen");
    expect(punycodeDecode("bcher-kva")).toBe("bücher");
    expect(punycodeDecode("ihqwcrb4cv8a8dqg056pqjye")).toBe("他们为什么不说中文");
    expect(punycodeDecode("!!")).toBeNull();
    expect(hostToUnicode("xn--pple-43d.com")).toBe("аpple.com");
    expect(hostToUnicode("xn--!!.com")).toBe("xn--!!.com");
  });
  it("shows an internationalised host both ways, and warns when a label mixes alphabets", () => {
    expect(displayHost("example.com")).toBe("example.com");
    expect(displayHost("xn--mnchen-3ya.de")).toBe("münchen.de (xn--mnchen-3ya.de)");
    expect(mixesScripts("аpple.com")).toBe(true);
    expect(displayHost("xn--pple-43d.com")).toBe("аpple.com (xn--pple-43d.com) - mixes alphabets, may imitate another site");
    expect(displayUrlHost("https://xn--pple-43d.com/login")).toContain("(xn--pple-43d.com)");
    expect(displayUrlHost("https://example.com/x")).toBe("https://example.com/x");
  });
  it("the blocked page and the approval title use it", () => {
    expect(explanationFor({ rule: "nav.suspicious_host", host: "xn--pple-43d.com", chars: "3" }).host).toContain("(xn--pple-43d.com)");
    expect(approvalTitle({ subject: "action", actionClass: "payment", domain: "xn--pple-43d.com" })).toContain("аpple.com (xn--pple-43d.com)");
  });
});
