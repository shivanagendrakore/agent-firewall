/**
 * Hardening of the network, SQL, catastrophic-command, MCP-name and host-tool checks: each case is a spelling
 * the checks used to miss (a backslash-quote, a DO block, a versioned Discord webhook path, an IPv4-mapped
 * loopback, a path hidden in Artifact's `files` map...), plus the benign neighbour that must stay allowed.
 */
import { describe, expect, it } from "vitest";
import { catastrophicCommand, catastrophicPush, catastrophicSql } from "../src/engine/catastrophic.js";
import { toolKind } from "../src/engine/mcp.js";
import { hostMatches, isCaptureUrl, isLoopback, isMetadataEndpoint, parseUrlLike, urlsIn } from "../src/engine/network.js";
import { classifyAnswer } from "../src/engine/netgate.js";
import { classifySql } from "../src/engine/sql.js";
import { explain, run } from "./helpers.js";

describe("Artifact publish: the sources in `files` are paths", () => {
  it("a credential file named as a published file's source is asked about", () => {
    const readFile = () => "<p>page</p>";
    for (const input of [
      { file_path: "/tmp/a.html", files: { "x.txt": "/Users/dev/.aws/credentials" } },
      { file_path: "/tmp/a.html", files: { "x.txt": { from: "/Users/dev/.aws/credentials" } } },
      { file_path: "/tmp/a.html", files: [{ path: "/Users/dev/.aws/credentials" }] },
    ]) {
      const d = run("Artifact", input, { ctx: { readFile } });
      expect(d.rules, explain(d)).toContain("FW-CREDENTIAL-READ");
      expect(d.verdict, explain(d)).toBe("ask");
    }
  });
  it("an ordinary multi-file publish is still allowed", () => {
    const d = run("Artifact", { file_path: "/Users/dev/proj/index.html", files: { "style.css": "/Users/dev/proj/style.css" }, root: "/Users/dev/proj" }, { ctx: { readFile: () => "body{}" } });
    expect(d.verdict, explain(d)).toBe("allow");
  });
});

describe("SQL", () => {
  it("a backslash before a quote does not hide a statement from the readers that take it literally", () => {
    const r = classifySql("SELECT 'x\\'; DROP TABLE users; -- '");
    expect(r.destroys).toBe(true);
    expect(r.opaque).toBe(true);
    expect(classifySql("select 'a\\\\' ; drop table t").destroys).toBe(true);
    expect(classifySql("select 'it''s fine'").destroys).toBe(false);
  });
  it("a DO block's body is judged as statements", () => {
    expect(catastrophicSql("DO $$ BEGIN DROP SCHEMA public CASCADE; END $$;", false)).not.toBeNull();
    expect(classifySql("DO $$ BEGIN DROP TABLE users; END $$;").destroys).toBe(true);
    expect(classifySql("DO $$ BEGIN INSERT INTO t VALUES (1); END $$;").destroys).toBe(false);
  });
  it("a WHERE inside a sub-select, or one that is always true, does not make a DELETE or UPDATE targeted", () => {
    expect(classifySql("delete from t where 1=1").destroys).toBe(true);
    expect(classifySql("delete from t where true").destroys).toBe(true);
    expect(classifySql("update t set a = 1 where (1 = 1)").destroys).toBe(true);
    expect(classifySql("delete from t using (select id from u where x = 1) s").destroys).toBe(true);
    expect(classifySql("update t set a = (select max(b) from u where c = 1)").destroys).toBe(true);
    expect(classifySql("delete from t where id = 1").destroys).toBe(false);
    expect(classifySql("delete from t where id in (select id from u where x = 1)").destroys).toBe(false);
    expect(classifySql("delete from t where 1=1 and id = 5").destroys).toBe(false);
  });
  it("a data-modifying CTE is judged by its body", () => {
    expect(classifySql("WITH d AS (DELETE FROM users RETURNING *) SELECT count(*) FROM d").destroys).toBe(true);
    expect(classifySql("WITH d AS (DELETE FROM users WHERE id = 1 RETURNING *) SELECT count(*) FROM d").destroys).toBe(false);
    expect(classifySql("WITH a AS (SELECT 1) SELECT * FROM a").destroys).toBe(false);
  });
  it("SQL under the argument names query, queries, sql_statements, statement, script and command is judged", () => {
    for (const key of ["query", "queries", "sql_statements", "sqlStatements", "statements", "script", "command"]) {
      const d = run("mcp__supabase__execute_sql", { [key]: "drop database postgres" });
      expect(d.verdict, `${key}: ${explain(d)}`).toBe("deny");
      expect(d.rules).toContain("FW-CATASTROPHIC");
    }
  });
});

describe("network", () => {
  it("a Discord webhook under a versioned API path is a capture URL", () => {
    for (const u of ["https://discord.com/api/webhooks/1/abc", "https://discord.com/api/v10/webhooks/1/abc", "https://discordapp.com/api/v9/webhooks/1/abc"]) {
      const p = parseUrlLike(u);
      expect(p !== null && isCaptureUrl(p), u).toBe(true);
    }
    const other = parseUrlLike("https://discord.com/api/v10/users/@me");
    expect(other !== null && isCaptureUrl(other)).toBe(false);
  });
  it("an IPv4-mapped loopback is loopback in either spelling, and a mapped public address is not", () => {
    expect(isLoopback("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopback("::ffff:7f00:1")).toBe(true);
    expect(isLoopback("0:0:0:0:0:0:0:1")).toBe(true);
    expect(isLoopback("::ffff:8.8.8.8")).toBe(false);
    expect(isLoopback("::ffff:808:808")).toBe(false);
  });
  it("an IPv6 literal URL in free text keeps its closing bracket", () => {
    expect(urlsIn("curl http://[::1]:8080/x").map((u) => u.host)).toEqual(["::1"]);
    expect(urlsIn("see (https://example.com/a), and [https://example.org/b]").map((u) => u.host)).toEqual(["example.com", "example.org"]);
  });
  it("a host pattern with a scheme, port or leading dot still matches", () => {
    for (const p of ["https://example.com", "example.com:8443", ".example.com", "https://example.com:8443/path", "EXAMPLE.com."]) expect(hostMatches("api.example.com", p), p).toBe(true);
    expect(hostMatches("example.com", "=https://example.com")).toBe(true);
    expect(hostMatches("example.com", "*.example.com")).toBe(false);
    expect(hostMatches("api.example.com", "*.example.com")).toBe(true);
    expect(hostMatches("example.org", "https://example.com")).toBe(false);
    expect(hostMatches("notexample.com", ".example.com")).toBe(false);
  });
  it("EKS Pod Identity and any spelling of the IPv6 metadata addresses are metadata endpoints", () => {
    for (const h of ["169.254.170.23", "fd00:ec2::23", "fd00:ec2::254", "FD00:EC2:0:0:0:0:0:254", "[fd00:ec2:0::23]"]) expect(isMetadataEndpoint(h), h).toBe(true);
    expect(isMetadataEndpoint("fd00:ec2::25")).toBe(false);
    expect(classifyAnswer("fd00:ec2:0:0:0:0:0:254").kind).toBe("never");
  });
});

describe("catastrophic commands", () => {
  it("a whole bucket named with a glob is a whole bucket", () => {
    expect(catastrophicCommand("gsutil", ["rm", "-r", "gs://prod-data/**"])).not.toBeNull();
    expect(catastrophicCommand("gcloud", ["storage", "rm", "-r", "gs://prod-data/*"])).not.toBeNull();
    expect(catastrophicCommand("gsutil", ["rm", "-r", "gs://prod-data/tmp/**"])).toBeNull();
  });
  it("a force push of a glob refspec rewrites the protected branches it matches", () => {
    expect(catastrophicPush(["--force", "origin", "refs/heads/*:refs/heads/*"])).not.toBeNull();
    expect(catastrophicPush(["-f", "origin", "+refs/heads/*:refs/heads/*"])).not.toBeNull();
    expect(catastrophicPush(["--force", "origin", "refs/heads/feature/*:refs/heads/feature/*"])).toBeNull();
  });
  it("flyctl's singular and short spellings reach the Fly.io entries", () => {
    expect(catastrophicCommand("fly", ["app", "destroy", "prod1"])).not.toBeNull();
    expect(catastrophicCommand("fly", ["app", "delete", "prod1"])).not.toBeNull();
    expect(catastrophicCommand("fly", ["vol", "destroy", "vol_1"])).not.toBeNull();
    expect(catastrophicCommand("fly", ["vol", "delete", "vol_1"])).not.toBeNull();
    expect(catastrophicCommand("fly", ["app", "list"])).toBeNull();
  });
  it("kubectl delete of a namespace is denied, and a client or server dry run is not", () => {
    expect(catastrophicCommand("kubectl", ["delete", "namespace", "prod"])).not.toBeNull();
    expect(catastrophicCommand("kubectl", ["delete", "namespace", "prod", "--dry-run=client"])).toBeNull();
    expect(catastrophicCommand("kubectl", ["delete", "namespace", "prod", "--dry-run=server"])).toBeNull();
    expect(catastrophicCommand("kubectl", ["delete", "namespace", "prod", "--dry-run=none"])).not.toBeNull();
  });
});

describe("MCP tool names", () => {
  const p = { results: "untrusted" as const, privateData: true };
  it("a tool that reads and then writes is a send", () => {
    for (const t of ["get_or_create_user", "get_and_set_value", "search_and_replace", "find_and_replace", "getOrCreateUser"]) expect(toolKind(t, p), t).toBe("send");
  });
  it("replace and clear are writes, and kill, uninstall, prune, flush and empty are destructive", () => {
    expect(toolKind("replace_text", p)).toBe("send");
    expect(toolKind("clear_cache_entry", p)).toBe("send");
    for (const t of ["kill_process", "uninstall_package", "prune_images", "flush_queue", "empty_trash"]) expect(toolKind(t, p), t).toBe("destroy");
  });
  it("ordinary reads stay reads, and a policy read list still wins", () => {
    for (const t of ["get_issue", "list_open_issues", "search_users", "get_user_and_teams"]) expect(toolKind(t, p), t).toBe("read");
    expect(toolKind("get_or_create_user", { ...p, readTools: ["get_or_create_user"] })).toBe("read");
  });
});
