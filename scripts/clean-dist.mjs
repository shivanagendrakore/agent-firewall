// Every build starts from an empty dist/ (the first step of "build", so prepack too). tsc only writes and
// overwrites, so a module whose source was deleted or renamed would stay in dist/, and "files" in
// package.json ships the whole directory: a hand publish from a working copy would carry it.
//
// It removes only the dist/ beside this script's own package (found from this file, never from the working
// directory), and only when that package.json names this package. A dist/ that is a symbolic link is
// removed as a link; what it points to is left alone.
import { lstatSync, readFileSync, rmSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";

const NAME = "@launchsafe/agent-firewall";
const root = new URL("../", import.meta.url);
const manifest = new URL("package.json", root);

let name;
try {
  ({ name } = JSON.parse(readFileSync(manifest, "utf8")));
} catch (e) {
  console.error(`clean-dist: cannot read ${fileURLToPath(manifest)} (${e.message.split("\n")[0]}). dist/ was not removed.`);
  process.exit(1);
}
if (name !== NAME) {
  console.error(`clean-dist: ${fileURLToPath(manifest)} names ${JSON.stringify(name)}, not ${NAME}. dist/ was not removed.`);
  process.exit(1);
}
const dist = new URL("dist", root);
// The link itself is unlinked here rather than left to rmSync, whose handling then does not matter.
if (lstatSync(dist, { throwIfNoEntry: false })?.isSymbolicLink() === true) unlinkSync(dist);
else rmSync(dist, { recursive: true, force: true });
