/**
 * A dense table that exercises the remaining command handlers: every one must
 * classify without throwing and reach a sensible verdict. This both broadens
 * coverage of the analyzer and documents how each family is treated.
 */

import { describe, expect, it } from "vitest";
import { classifyAction } from "../src/engine/classify.js";
import { defaultConfig } from "../src/policy.js";
import { emptyState } from "../src/engine/state.js";
import { bash, ctx, explain, run } from "./helpers.js";

function eff(cmd: string): string[] {
  return classifyAction({ tool: "Bash", input: { command: cmd } }, ctx(), defaultConfig(), emptyState()).effects.map((e) => e.cls);
}

describe("every command classifies without throwing and reaches a valid verdict", () => {
  const commands: string[] = [
    // wrappers
    "sudo -u deploy ls", "doas pkg_add x", "env -i PATH=/bin ls", "nice -n 10 make", "nohup ./run.sh &", "timeout 30 npm test",
    "xargs -I{} rm {} < list", "parallel echo ::: a b c", "flock /tmp/l -c 'echo hi'", "watch -n5 'git status'", "stdbuf -oL ./app",
    "strace -f ./app", "setsid ./daemon", "chrt -f 99 ./rt", "taskset -c 0 ./app",
    // readers / search
    "bat src/index.ts", "xxd binary | head", "strings /bin/ls", "od -c file", "hexdump -C file", "shasum -a 256 file",
    "jq -r '.name' p.json", "yq '.services' compose.yml", "rg -l TODO", "ag pattern", "ack foo src", "column -t data.tsv",
    "sqlite3 db.sqlite '.tables'", "duckdb -c 'select 1'", "tr a-z A-Z < f", "nl file", "fold -w80 f", "tail -n100 log",
    // writers / fs
    "truncate -s 0 tmp.log", "install -d build", "mkfifo /tmp/pipe", "chmod 755 run.sh", "chmod u+s /tmp/x",
    "chown -R me:me build", "setfacl -m u:me:rw f", "ln -s target link", "mktemp -d", "shred -u secret.txt",
    "cp -r a b", "mv a b", "dd if=/dev/zero of=test.img bs=1M count=10", "rsync -av a/ b/",
    // archives
    "tar -cf out.tar src", "tar -tf out.tar", "gzip file", "gunzip file.gz", "xz -d file.xz", "zstd -d file.zst",
    "7z x archive.7z", "unzip -l data.zip", "jar cf out.jar classes", "cpio -o < list",
    // git
    "git rebase -i HEAD~3", "git reset --hard HEAD", "git clean -fd", "git stash drop", "git worktree add ../wt",
    "git tag v1.0", "git bisect start", "git submodule update --init", "git remote add origin url", "git gc",
    "git reflog expire --all", "git filter-branch --tree-filter x HEAD", "git cherry-pick abc", "git revert HEAD",
    "git format-patch -o patches main", "git bundle create r.bundle main", "git difftool", "git lfs pull",
    // forge
    "gh issue list", "gh pr merge 12", "gh release create v1", "gh gist create f.txt", "gh repo clone a/b",
    "gh workflow run ci.yml", "gh secret set TOKEN", "glab mr create", "gh extension install owner/ext",
    // package managers
    "pnpm add react", "yarn add -D jest", "bun add zod", "pip install flask", "poetry add requests", "cargo add tokio",
    "gem install rails", "composer require x/y", "go get example.com/pkg", "npm run build", "npm publish --dry-run",
    "brew install wget", "apt-get install -y curl", "pipx install black", "uv pip install ruff", "deno install -n x url",
    "npm uninstall lodash", "npm ls", "npm outdated", "cargo build --release", "go build ./...",
    // interpreters inline
    "ruby -e 'puts 1'", "php -r 'echo 1;'", "perl -E 'say 1'", "lua -e 'print(1)'", "deno eval 'console.log(1)'",
    "Rscript -e 'print(1)'", "python3 -m http.server 8000", "python3 -m venv .venv", "node --require ./preload.js app.js",
    // cloud / infra
    "aws ec2 describe-instances", "aws s3 ls s3://b", "aws iam create-user --user-name x", "gcloud compute instances list",
    "kubectl apply -f deploy.yml", "kubectl exec pod -- ls", "helm install app ./chart", "terraform apply -auto-approve",
    "pulumi up", "doctl droplet list", "flyctl deploy", "vercel env pull", "wrangler publish", "stripe charges list",
    "docker build -t x .", "docker exec c ls", "docker volume rm v", "docker login", "podman run img",
    // db clients
    "mysql -h db.example.com -e 'show tables'", "mongosh 'mongodb://db.example.com' --eval 'db.x.find()'",
    "psql -h db.example.com -c 'create table t(id int)'", "clickhouse-client --query 'select 1'",
    // system
    "systemctl status nginx", "systemctl enable app", "launchctl list", "defaults write com.x key val",
    "diskutil list", "crontab -l", "at now + 1 hour", "security dump-keychain", "dscl . -read /Users/me",
    // network
    "http GET https://api.example.com/x", "xh POST https://api.example.com/y a=1", "aria2c https://example.com/f",
    "nc -l 9000", "socat TCP-LISTEN:8080 -", "ssh -R 9000:localhost:22 host.example.com", "mail -s hi a@b.com",
    "cloudflared tunnel run", "open https://example.com", "redis-cli -h cache.example.com ping",
    // editors / clipboard / misc
    "code --install-extension ms.python", "vim -c 'wq' file", "pbcopy < f", "xclip -sel clip -o",
    "make install", "just deploy", "bazel build //...", "npx create-react-app my-app", "bunx cowsay hi",
  ];
  for (const cmd of commands) {
    it(cmd.slice(0, 55), () => {
      expect(() => eff(cmd)).not.toThrow();
      const d = bash(cmd);
      expect(["allow", "ask", "queue", "deny"], explain(d)).toContain(d.verdict);
      const u = bash(cmd, { tainted: true });
      expect(["allow", "ask", "queue", "deny"], explain(u)).toContain(u.verdict);
    });
  }
});

describe("non-Bash and MCP tools classify without throwing", () => {
  const cases: { tool: string; input: Record<string, unknown> }[] = [
    { tool: "WebFetch", input: { url: "https://example.com" } },
    { tool: "WebSearch", input: { query: "how to x" } },
    { tool: "NotebookEdit", input: { notebook_path: "/Users/dev/proj/nb.ipynb", new_source: "print(1)" } },
    { tool: "NotebookRead", input: { notebook_path: "/Users/dev/proj/nb.ipynb" } },
    { tool: "MultiEdit", input: { file_path: "/Users/dev/proj/x.ts", edits: [{ old_string: "a", new_string: "b" }] } },
    { tool: "ReadMcpResourceTool", input: { server: "github", uri: "repo://acme/app/readme" } },
    { tool: "mcp__linear__list_issues", input: { teamId: "T1" } },
    { tool: "mcp__slack__post_message", input: { channel: "#general", text: "hi" } },
    { tool: "mcp__memory__create_entities", input: { entities: [] } },
    { tool: "mcp__notion__delete_page", input: { page_id: "p1" } },
    { tool: "mcp__fetch__fetch", input: { url: "https://example.com" } },
    { tool: "mcp__puppeteer__navigate", input: { url: "https://evil.example.com" } },
    { tool: "mcp__postgres__query", input: { sql: "select * from users" } },
    { tool: "mcp__unknownserver__do_thing", input: { x: 1 } },
    { tool: "SomeUnknownTool", input: { path: "/etc/passwd", url: "https://x.example.com" } },
    { tool: "PowerShell", input: { command: "Get-ChildItem" } },
  ];
  for (const c of cases) {
    it(`${c.tool}`, () => {
      const d = run(c.tool, c.input);
      expect(["allow", "ask", "queue", "deny"], explain(d)).toContain(d.verdict);
      const u = run(c.tool, c.input, { tainted: true });
      expect(["allow", "ask", "queue", "deny"], explain(u)).toContain(u.verdict);
    });
  }
});
