// The CLI is the hook command Claude Code runs and the launchsafe-firewall binary: it must start with
// a shebang (kept from src/cli.ts by tsc) and be executable after every build, including the one the
// test suite runs.
import { chmodSync, readFileSync } from "node:fs";
const bin = new URL("../dist/cli.js", import.meta.url);
if (!readFileSync(bin, "utf8").startsWith("#!/usr/bin/env node")) throw new Error("dist/cli.js has no shebang");
chmodSync(bin, 0o755);
