/**
 * Integration tests run offline: fetch and raw sockets throw (and are counted) for the whole file, so
 * a framework, a test model or the firewall reaching for the network fails the test.
 */

import net from "node:net";
import { afterAll, beforeAll, expect } from "vitest";

export function noNetwork(): { calls: () => number } {
  let calls = 0;
  const realFetch = globalThis.fetch;
  const realConnect = net.Socket.prototype.connect;
  beforeAll(() => {
    globalThis.fetch = ((input: unknown) => {
      calls++;
      throw new Error(`network used in a test: fetch ${String(input)}`);
    }) as typeof fetch;
    net.Socket.prototype.connect = function () {
      calls++;
      throw new Error("network used in a test: socket connect");
    } as never;
  });
  afterAll(() => {
    globalThis.fetch = realFetch;
    net.Socket.prototype.connect = realConnect;
    expect(calls, "network calls during this file").toBe(0);
  });
  return { calls: () => calls };
}
