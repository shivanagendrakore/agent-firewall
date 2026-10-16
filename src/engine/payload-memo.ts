/**
 * Review of FZ17: one call's arguments can become many egress effects that all carry the same payload (every
 * URL in an MCP call's arguments is one effect with the whole arguments as payload), and the data rules scanned
 * the payload once per effect: hundreds of full scans of up to 1 MiB in one decision. These wrappers remember
 * the last result of a pure scan by argument identity, and decide() forgets them at the start of every decision,
 * so a payload is scanned once per decision however many effects carry it. Browser-safe.
 *
 * memoLast keys by strings and other values compared with ===, which cannot change. memoByInput keys by an
 * object's identity, and an object can change (a library caller that reuses and edits one input object between
 * calls): so it remembers only inside a decision (inDecision(), which decide() and decideNative() run in), where
 * nothing changes the input, and outside one every call computes afresh.
 */

const resets: (() => void)[] = [];
/** How many decisions are running (decideNative runs decide inside its own). */
let depth = 0;

/** `f` with a one-entry memory keyed by its arguments (===). Only for pure functions of their arguments. */
export function memoLast<A extends readonly unknown[], R>(f: (...a: A) => R): (...a: A) => R {
  let key: A | undefined;
  let value: R;
  resets.push(() => {
    key = undefined;
  });
  return (...a: A): R => {
    if (key !== undefined && key.length === a.length && key.every((x, i) => x === a[i])) return value;
    value = f(...a);
    key = a;
    return value;
  };
}

/**
 * Memory keyed by an object's identity (a tool call's input) and a string (its tool), used only while a
 * decision runs (inDecision) and forgotten when one starts and when the outermost one ends. Only for pure
 * functions of the object's content: actionHash and learnKey hash one input several times per decision (the
 * rules, the budgets, the spending limits, the learned choices).
 */
export function memoByInput<R>(f: (tool: string, input: object) => R): (tool: string, input: object) => R {
  let memo = new WeakMap<object, Map<string, R>>();
  resets.push(() => {
    memo = new WeakMap();
  });
  return (tool: string, input: object): R => {
    // Outside a decision the input may have been edited since it was last seen: never a remembered result.
    if (depth === 0) return f(tool, input);
    let m = memo.get(input);
    if (m === undefined) {
      m = new Map();
      memo.set(input, m);
    }
    if (m.has(tool)) return m.get(tool) as R;
    const v = f(tool, input);
    if (m.size < 16) m.set(tool, v);
    return v;
  };
}

/** Forgets every remembered result (called when a decision starts, so nothing outlives the state it read). */
export function newDecisionMemo(): void {
  for (const r of resets) r();
}

/** Runs one decision with memoByInput's memory on, forgetting it on the way in and when the outermost one ends. */
export function inDecision<T>(f: () => T): T {
  if (depth === 0) newDecisionMemo();
  depth++;
  try {
    return f();
  } finally {
    depth--;
    if (depth === 0) newDecisionMemo();
  }
}
