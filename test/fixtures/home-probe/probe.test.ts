import { expect, it } from "vitest";

it("never runs: the setup assertion fails the file first", () => {
  expect(true).toBe(true);
});
