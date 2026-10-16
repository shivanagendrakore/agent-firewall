/**
 * FZ14 (test/fuzz/found.test.ts): a tool call's arguments nested thousands of levels deep overflowed the
 * stack inside decide() (canonicalJson is recursive), and the failure policy then let a read-only tool through
 * unchecked: `Read ~/.ssh/id_rsa` with an extra argument holding [[[[...]]]] was allowed. So the engine refuses
 * arguments deeper than MAX_INPUT_DEPTH before it judges anything, and an error that came from the shape of
 * the input (this refusal, or a stack overflow anywhere) is never one a read-only tool may proceed through.
 * Browser-safe; no recursion here (the check itself must not overflow).
 */

/** The deepest nesting of a tool's arguments the engine judges. Real tool arguments are a few levels deep; the vault tests judge 70 (V17); the recursive walks overflow in the thousands. */
export const MAX_INPUT_DEPTH = 256;

/** More objects and arrays than this in one call's arguments are not walked (a 1 MiB JSON body holds far fewer). */
const MAX_NODES = 2_000_000;

/** The arguments were nested deeper than MAX_INPUT_DEPTH: the call was not judged. */
export class InputTooDeep extends Error {
  constructor(message = `the tool's arguments are nested deeper than ${MAX_INPUT_DEPTH} levels`) {
    super(message);
    this.name = "InputTooDeep";
  }
}

/** Whether `v` has arrays or objects nested deeper than `max` (the value itself is depth 1), or too many of them. Iterative. */
export function nestedDeeperThan(v: unknown, max: number): boolean {
  const stack: [unknown, number][] = [[v, 1]];
  // A cycle (only possible from a caller in the same process) grows the depth until it is over `max`; a value
  // that shares objects many times over is cut off by the node count.
  let nodes = 0;
  while (stack.length > 0) {
    const [x, d] = stack.pop() as [unknown, number];
    if (typeof x !== "object" || x === null) continue;
    if (d > max || ++nodes > MAX_NODES) return true;
    const children = Array.isArray(x) ? x : Object.values(x as Record<string, unknown>);
    for (const c of children) if (typeof c === "object" && c !== null) stack.push([c, d + 1]);
  }
  return false;
}

/** The rule a call refused for its input's shape carries (a deny; doctor counts them in the decision log). */
export const RULE_INPUT_SHAPE = "FW-INPUT-SHAPE";

/**
 * Whether a decision error came from the input's shape: InputTooDeep, or a RangeError the input's size or depth
 * causes (a stack overflow, a string past the engine's maximum length). Such an error is the input's doing, so
 * the "read-only tools proceed when deciding fails" policy never applies to it. Any other RangeError (a bad
 * Date, an invalid array length from a bug) is an internal error like any other.
 */
export function isInputShapeError(e: unknown): boolean {
  if (e instanceof InputTooDeep || (e instanceof Error && e.name === "InputTooDeep")) return true;
  return e instanceof RangeError && /Maximum call stack|Invalid string length/.test(e.message);
}
