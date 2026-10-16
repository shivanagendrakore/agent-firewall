/**
 * Shell constructs a review found returned allow-with-no-effects while bash or zsh runs them (SH1 to SH19,
 * and `enable -f`). Each is either modelled exactly (the hidden command is seen) or, when it cannot be, the
 * command is unclassifiable or opaque. A harmless-looking payload hides a destructive action; the firewall
 * must not allow it. Ordinary uses of the same constructs stay allowed (no new friction).
 */
import { describe, expect, it } from "vitest";
import { bash, explain } from "./helpers.js";

/** A destructive probe: the construct must surface it (a non-allow verdict), trusted and untrusted. */
const ROOT = "rm -rf ~";
/** A command the firewall sees but cannot know the contents of: allowed in a trusted session, asked once untrusted. */
function expectOpaque(cmd: string): void {
  expect(bash(cmd).verdict, explain(bash(cmd))).toBe("allow");
  const u = bash(cmd, { tainted: true });
  expect(u.verdict, explain(u)).not.toBe("allow");
}
function expectCaught(cmd: string): void {
  for (const tainted of [false, true]) {
    const d = bash(cmd, { tainted });
    expect(d.verdict, explain(d)).not.toBe("allow");
  }
}

describe("hidden commands in builtins and shell constructs are not silent allows", () => {
  const caught: [string, string][] = [
    ["SH1: $[...] legacy arithmetic with a substitution", `echo $[1 + $(${ROOT})]`],
    ["SH1: $[...] with a << that is not a here-doc", `echo $[$(${ROOT}) << 2]`],
    ["SH3: a substitution in an unquoted here-document body", `cat <<EOF\n$(${ROOT})\nEOF`],
    ["SH3: a backtick substitution in an unquoted here-document", `cat <<EOF\n\`${ROOT}\`\nEOF`],
    ["SH5: trap with a handler after options", `trap -- '${ROOT}' EXIT`],
    ["SH5: trap with a plain handler", `trap '${ROOT}' EXIT`],
    ["SH6: hash -p remaps a later command name", `hash -p /bin/rm ls; ls -rf ~`],
    ["SH7: jobs -x runs a command", `jobs -x ${ROOT}`],
    ["SH8: mapfile -C callback", `mapfile -C '${ROOT}' -c 1 arr < package.json`],
    ["SH8: readarray -C callback", `readarray -C '${ROOT}' arr < package.json`],
    ["SH9: let with a subscript substitution", `let 'a[$(${ROOT})]=1'`],
    ["SH9: [[ -eq ]] with a subscript substitution", `[[ a[$(${ROOT})] -eq 1 ]]`],
    ["SH9: [[ -v ]] with a quoted subscript substitution", `[[ -v 'a[$(${ROOT})]' ]]`],
    ["SH9: test -v with a quoted subscript substitution", `test -v 'a[$(${ROOT})]'`],
    ["SH9: declare with a quoted subscript substitution", `declare 'a[$(${ROOT})]=1'`],
    ["SH9: local with a quoted subscript substitution", `local 'a[$(${ROOT})]'`],
    ["SH9: read with a quoted subscript substitution", `read 'a[$(${ROOT})]' < package.json`],
    ["SH9: printf -v with a quoted subscript substitution", `printf -v 'a[$(${ROOT})]' x`],
    ["SH9: unset with a quoted subscript substitution", `unset 'a[$(${ROOT})]'`],
    ["SH10: an array assignment body", `a=( $(${ROOT}) )`],
    ["SH11: brace expansion building the program name", "{rm,-rf,~}"],
    ["SH4: coproc with a named group body (the body is modelled)", `coproc NAME { ${ROOT}; }`],
    ["SH4: coproc with a simple command", `coproc ${ROOT}`],
    ["SH16: zsh repeat", `repeat 2 ${ROOT}`],
    ["SH19: zsh - precommand modifier", `- ${ROOT}`],
  ];
  for (const [what, cmd] of caught) {
    it(what, () => expectCaught(cmd));
  }

  const opaque: [string, string][] = [
    ["SH12: a shell reading its script from a process substitution", `sh < <(echo ${ROOT})`],
    ["SH12: bash run on a process substitution", `bash <(echo ${ROOT})`],
    ["enable -f loads a builtin from a shared object", "enable -f ./x.so x; x"],
  ];
  for (const [what, cmd] of opaque) {
    it(what, () => expectOpaque(cmd));
  }

  const unclassifiable: [string, string][] = [
    ["SH13: zsh =(...) process substitution", `cat =(${ROOT})`],
    ["SH14: zsh glob qualifier that runs code", "ls *(e:'echo hi':)"],
    ["SH15: zsh always block", `{ echo hi } always { ${ROOT} }`],
    ["SH17: zsh short for loop", `for x (a b) ${ROOT}`],
    ["SH17: zsh foreach loop", "foreach x (a b)"],
    ["SH18: zsh short if", `if [[ -d . ]] ${ROOT}`],
  ];
  for (const [what, cmd] of unclassifiable) {
    it(what, () => expectCaught(cmd));
  }
});

describe("ordinary uses of those builtins stay allowed", () => {
  const fine: string[] = [
    "trap 'echo done' EXIT",
    "trap 'rm -f /tmp/mytmp' EXIT",
    "trap - INT",
    "declare -i x=5",
    "declare -a arr",
    "read -r line < package.json",
    "read -rp \"continue? \" answer",
    "printf -v var '%s' hello",
    "mapfile -t lines < package.json",
    "readarray -t lines < package.json",
    "hash -r",
    "hash npm node",
    "jobs -l",
    "let x=1+2",
    "let \"y = x * 3\"",
    "[[ -f package.json && -d src ]]",
    "[[ $x -eq 5 ]]",
    "test -v HOME",
    "echo $[1 + 2 * 3]",
    "enable -n kill",
    "cat > out.txt <<EOF\nbuilt $(git rev-parse --short HEAD)\nEOF",
    "cat <<'EOF'\nliteral $(not run)\nEOF",
    "diff <(sort a.txt) <(sort b.txt)",
    "cat <(grep foo src/index.ts)",
  ];
  for (const cmd of fine) {
    it(JSON.stringify(cmd), () => {
      for (const tainted of [false, true]) {
        const d = bash(cmd, { tainted });
        expect(d.verdict, explain(d)).toBe("allow");
      }
    });
  }
});
