/**
 * FW-CATASTROPHIC, table by table: one synthesized command per entry of the catastrophic command tables
 * (src/engine/catastrophic.ts), denied through the whole engine in a trusted, an untrusted and an unattended
 * session; and, for every entry that matches only under a condition (`when`) or that a targeted form demotes
 * (`demote`), a near miss that stays an approvable question. A new table entry without a probe here fails the
 * coverage test, so the table cannot grow untested. Every command is data for the engine: none is run.
 */
import { describe, expect, it } from "vitest";
import { catastrophicAliases, catastrophicTableEntries, type CatastrophicEntrySummary } from "../src/engine/catastrophic.js";
import { bash, explain } from "./helpers.js";

const SESSIONS = [
  { name: "trusted", o: {} },
  { name: "untrusted", o: { tainted: true } },
  { name: "unattended", o: { ctx: { interactive: false } } },
] as const;

interface Probe {
  /** The catastrophic form. */
  cmd: string;
  /** Near misses: the condition not met (when) or a targeted form (demote). Each stays an approvable question. */
  near?: string[];
}

/** Entries whose default probe (`TOOL PATH prod1`) would not show the entry, or that need near misses. */
const PROBES: Record<string, Probe> = {
  "aws s3 rb": { cmd: "aws s3 rb s3://prod-data" },
  "aws s3 rm": {
    cmd: "aws s3 rm s3://prod-data --recursive",
    near: ["aws s3 rm s3://prod-data/tmp/ --recursive", "aws s3 rm s3://prod-data/report.csv", "aws s3 rm s3://prod-data --recursive --exclude '*' --include 'tmp/*'"],
  },
  "aws ecr delete-repository": { cmd: "aws ecr delete-repository --repository-name app --force", near: ["aws ecr delete-repository --repository-name app"] },
  "gcloud storage buckets delete": { cmd: "gcloud storage buckets delete gs://prod-data" },
  "gcloud storage rm": { cmd: "gcloud storage rm -r gs://prod-data", near: ["gcloud storage rm -r gs://prod-data/tmp/", "gcloud storage rm gs://prod-data/file.txt"] },
  "gsutil rb": { cmd: "gsutil rb gs://prod-data" },
  "gsutil rm": { cmd: "gsutil rm -r gs://prod-data", near: ["gsutil rm -r gs://prod-data/tmp", "gsutil rm gs://prod-data/file.txt"] },
  "bq rm": { cmd: "bq rm -r -f proddataset", near: ["bq rm -f -t proddataset.events"] },
  "terraform destroy": { cmd: "terraform destroy", near: ["terraform destroy -target=aws_instance.web"] },
  "terraform apply": { cmd: "terraform apply -destroy", near: ["terraform apply -destroy -target=aws_instance.web"] },
  "tofu destroy": { cmd: "tofu destroy", near: ["tofu destroy -target=aws_instance.web"] },
  "tofu apply": { cmd: "tofu apply -destroy", near: ["tofu apply -destroy -target=aws_instance.web"] },
  "terragrunt destroy": { cmd: "terragrunt destroy", near: ["terragrunt destroy -target=aws_instance.web"] },
  "terragrunt apply": { cmd: "terragrunt apply -destroy", near: ["terragrunt apply -destroy -target=aws_instance.web"] },
  "terragrunt destroy-all": { cmd: "terragrunt destroy-all", near: ["terragrunt destroy-all -target=aws_instance.web"] },
  "terragrunt apply-all": { cmd: "terragrunt apply-all -destroy", near: ["terragrunt apply-all -destroy -target=aws_instance.web"] },
  "pulumi destroy": { cmd: "pulumi destroy --yes", near: ["pulumi destroy --target urn:pulumi:dev::app::aws:s3/bucket:Bucket::logs"] },
  "pulumi apply": { cmd: "pulumi apply --destroy", near: ["pulumi apply --destroy --target urn:pulumi:dev::app::aws:s3/bucket:Bucket::logs"] },
  "pulumi up": { cmd: "pulumi up --destroy --yes", near: ["pulumi up --destroy --target urn:pulumi:dev::app::aws:s3/bucket:Bucket::logs"] },
  "docker volume prune": { cmd: "docker volume prune -f" },
  "docker system prune": { cmd: "docker system prune -af" },
  "docker compose down": { cmd: "docker compose down -v", near: ["docker compose down"] },
  "docker-compose down": { cmd: "docker-compose down --volumes", near: ["docker-compose down"] },
  "dropdb": { cmd: "dropdb app" },
  "mysqladmin drop": { cmd: "mysqladmin -u root drop shop" },
  "redis-cli flushall": { cmd: "redis-cli FLUSHALL" },
  "redis-cli flushdb": { cmd: "redis-cli -h cache.example.com flushdb" },
  "git reflog expire": { cmd: "git reflog expire --expire=now --all", near: ["git reflog expire --expire=90.days.ago --all"] },
  "supabase db reset": { cmd: "supabase db reset --linked", near: ["supabase db reset"] },
  "vercel remove": { cmd: "vercel remove my-project --yes", near: ["vercel remove my-app-abc123.vercel.app"] },
  "vercel rm": { cmd: "vercel rm my-project --yes", near: ["vercel rm my-app-abc123.vercel.app"] },
  "heroku apps:destroy": { cmd: "heroku apps:destroy --app myapp --confirm myapp" },
  "heroku pg:reset": { cmd: "heroku pg:reset DATABASE_URL" },
};

/** Near misses that are not destructive at all, so they are allowed rather than asked. */
const HARMLESS_NEAR = new Set(["docker compose down", "docker-compose down"]);

const key = (x: CatastrophicEntrySummary): string => [x.tool, ...x.path].join(" ");
const probeFor = (x: CatastrophicEntrySummary): Probe => PROBES[key(x)] ?? { cmd: `${key(x)} prod1` };

const ENTRIES = catastrophicTableEntries();

describe("the catastrophic tables are covered", () => {
  it("there are entries to probe", () => {
    expect(ENTRIES.length).toBeGreaterThan(80);
  });
  it("every conditional or demotable entry has a hand-written probe with near misses", () => {
    const missing = ENTRIES.filter((x) => (x.conditional || x.demotable) && (PROBES[key(x)]?.near ?? []).length === 0).map(key);
    expect(missing).toEqual([]);
  });
  it("no probe names an entry the tables no longer have", () => {
    const keys = new Set(ENTRIES.map(key));
    expect(Object.keys(PROBES).filter((k) => !keys.has(k))).toEqual([]);
  });
});

describe("FW-CATASTROPHIC: one command per table entry, denied in every session", () => {
  for (const x of ENTRIES) {
    const { cmd } = probeFor(x);
    it(`${key(x)}: ${cmd}`, () => {
      for (const s of SESSIONS) {
        const d = bash(cmd, s.o);
        expect(d.verdict, `${s.name}: ${explain(d)}`).toBe("deny");
        expect(d.rules, `${s.name}: ${explain(d)}`).toContain("FW-CATASTROPHIC");
        expect(d.reasons.join(" "), s.name).toContain(x.what);
      }
    });
  }
});

describe("near misses of conditional and demotable entries stay approvable questions", () => {
  for (const x of ENTRIES) {
    for (const cmd of probeFor(x).near ?? []) {
      it(`${key(x)}: ${cmd}`, () => {
        const d = bash(cmd);
        expect(d.findings.map((f) => f.id), explain(d)).not.toContain("catastrophic");
        expect(d.rules, explain(d)).not.toContain("FW-CATASTROPHIC");
        // Without -v, compose down removes containers and networks only: not destructive at all.
        const harmless = HARMLESS_NEAR.has(cmd);
        expect(d.verdict, explain(d)).toBe(harmless ? "allow" : "ask");
        // Unattended, the question is held for a person, never denied.
        const u = bash(cmd, { ctx: { interactive: false } });
        expect(u.verdict, explain(u)).toBe(harmless ? "allow" : "queue");
      });
    }
  }
});

describe("aliases reach the same tables", () => {
  const ALIAS_PROBES: Record<string, string> = {
    flyctl: "flyctl apps destroy myapp",
    podman: "podman volume prune -f",
    nerdctl: "nerdctl system prune -af",
    neon: "neon projects delete prod1",
    oc: "oc delete project prod",
  };
  it("every alias has a probe", () => {
    expect(Object.keys(catastrophicAliases()).sort()).toEqual(Object.keys(ALIAS_PROBES).sort());
  });
  for (const [alias, cmd] of Object.entries(ALIAS_PROBES)) {
    it(`${alias}: ${cmd}`, () => {
      for (const s of SESSIONS) {
        const d = bash(cmd, s.o);
        expect(d.verdict, `${s.name}: ${explain(d)}`).toBe("deny");
        expect(d.rules, `${s.name}: ${explain(d)}`).toContain("FW-CATASTROPHIC");
      }
    });
  }
});
