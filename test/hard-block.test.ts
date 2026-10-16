/**
 * The catastrophic class (FW-CATASTROPHIC, src/engine/catastrophic.ts) is denied in every session, every
 * permission mode and under every policy, approval or not; the near misses around it stay ordinary
 * destructive actions a person may approve. Every command here is data for the engine: none is run.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { actionHash } from "../src/engine/decide.js";
import { catastrophicCommand, catastrophicPush, catastrophicSql } from "../src/engine/catastrophic.js";
import { defaultConfig, mergeTighten, validatePolicy } from "../src/policy.js";
import { createGuard } from "../src/sdk/index.js";
import { toNative } from "../src/agent-replay.js";
import type { AgentId } from "../src/adapters/types.js";
import { RULES } from "../src/rules.js";
import { bash, explain, HOME, run, WS, type RunOpts } from "./helpers.js";
import { box, rules, send, verdict, type Box } from "./adapters/harness.js";

const CATASTROPHIC: string[] = [
  // The whole workspace.
  `rm -rf ${WS}`,
  "rm -rf .",
  "rm -rf ./*",
  "rm -rf *",
  `find ${WS} -delete`,
  `sudo rm -rf ${WS}`,
  "rm -rf /Users/dev/proj/",
  // The protected default branch.
  "git push --force origin main",
  "git push -f origin master",
  "git push -uf origin main",
  "git push origin +main",
  "git push --force-with-lease origin HEAD:main",
  "git push --force origin HEAD:refs/heads/main",
  "git push origin --delete main",
  "git push origin :trunk",
  "git push --mirror origin",
  "git -C ../other push -f origin main",
  // Databases.
  'psql -h db.prod.example.com -c "DROP DATABASE app"',
  "psql -c 'drop database app_dev'",
  'mysql -e "DROP SCHEMA shop"',
  "dropdb app",
  "mysqladmin -u root drop shop",
  'mongosh --eval "db.dropDatabase()"',
  "redis-cli FLUSHALL",
  "redis-cli -h cache.example.com flushdb",
  'psql -h db.example.com -c "TRUNCATE users"',
  // Cloud and infrastructure.
  "aws s3 rb s3://prod-data --force",
  "aws --profile prod s3 rb s3://prod-data",
  "aws s3 rm s3://prod-data --recursive",
  "aws s3api delete-bucket --bucket prod-data",
  "aws ec2 delete-volume --volume-id vol-0123456789abcdef0",
  "aws eks delete-cluster --name prod",
  "aws rds delete-db-instance --db-instance-identifier db1 --skip-final-snapshot",
  "aws cloudformation delete-stack --stack-name web",
  "gcloud projects delete my-project",
  "gcloud container clusters delete prod --zone us-central1-a",
  "gcloud compute disks delete disk-1",
  "gcloud sql instances delete db",
  "gcloud storage rm -r gs://prod-data",
  "gsutil -m rm -r gs://prod-data",
  "gsutil rb gs://prod-data",
  "az group delete --name prod-rg --yes",
  "az aks delete -g prod-rg -n prod",
  "az storage account delete -n prodacct",
  "kubectl delete namespace prod",
  "kubectl delete ns prod",
  "kubectl delete namespace/prod",
  "kubectl -n prod delete pvc data",
  "kubectl delete pods --all -A",
  "oc delete project prod",
  "eksctl delete cluster --name prod",
  "terraform destroy",
  "terraform destroy -auto-approve",
  "terraform -chdir=infra apply -destroy",
  "tofu destroy",
  "terragrunt run-all destroy",
  "pulumi destroy --yes",
  "cdk destroy --force",
  "railway delete",
  "railway volume delete pgdata",
  "fly apps destroy myapp",
  "fly destroy myapp",
  "flyctl volumes destroy vol_123",
  "vercel remove my-project --yes",
  "vercel project rm my-project",
  "supabase projects delete abcdefghij",
  "supabase db reset --linked",
  "heroku apps:destroy myapp --confirm myapp",
  "heroku pg:reset DATABASE_URL",
  "docker volume prune -f",
  "docker system prune -af",
  "docker compose down -v",
  "docker compose -f dev.yml down --volumes",
  "docker-compose down -v",
  // Repositories, keys, DNS, and the rest of the review's variants.
  "gh repo delete acme/app --yes",
  "gh api -X DELETE repos/acme/app",
  "gh api --method=DELETE /repos/acme/app",
  "aws kms schedule-key-deletion --key-id 1234abcd --pending-window-in-days 7",
  "aws route53 delete-hosted-zone --id Z123",
  "aws s3api delete-objects --bucket prod-data --delete file://keys.json",
  "aws ecr delete-repository --repository-name app --force",
  "rm -rf .git",
  `rm -rf ${WS}/.git`,
  "kubectl delete all --all",
  "kubectl delete crd widgets.example.com",
  "kubectl delete customresourcedefinitions widgets.example.com",
  "git reflog expire --expire=now --all",
  "pulumi up --destroy --yes",
  "git push --force origin production",
  "git push -f origin release/1.2",
  "git push --force origin develop",
  "git push --force --all origin",
  "heroku apps:destroy --app myapp --confirm myapp",
  "fly -a myapp destroy myapp --yes",
  "vercel remove my-project --scope my-team --yes",
  "terraform destroy --version",
  "redis-cli -h cache.example.com FLUSHALL",
  "podman system prune",
  // Reached through wrappers, nested shells and package runners.
  "npx vercel remove my-project",
  "npx supabase projects delete abcdefghij",
  "sudo terraform destroy",
  'bash -c "kubectl delete ns prod"',
  "env AWS_PROFILE=prod aws s3 rb s3://prod-data",
  "timeout 600 terraform destroy",
  "cd infra && terraform destroy",
];

/** Destructive, but not the catastrophic class: never denied as FW-CATASTROPHIC. */
const NEAR_MISSES: string[] = [
  "rm -rf node_modules",
  "rm -rf dist build",
  "git push --force origin feature-x",
  "git push --force",
  "git push -f origin main-redesign",
  "git push --dry-run --force origin main",
  "git push origin main",
  'psql -c "TRUNCATE users"',
  'psql -h db.example.com -c "DROP TABLE audit"',
  "kubectl delete pod web-1",
  "kubectl delete deployment web",
  "helm uninstall web",
  "terraform plan -destroy",
  "terraform destroy --help",
  "aws s3 rm s3://prod-data/tmp/ --recursive",
  "aws s3 rm s3://prod-data/report.csv",
  "gcloud storage rm gs://prod-data/file.txt",
  "docker rm web",
  "docker image prune -f",
  "vercel rm my-app-abc123.vercel.app",
  "supabase db reset",
  "fly machines destroy 3d8d9e1c",
  `chmod -R 755 ${WS}`,
  "kind delete cluster",
  "minikube delete",
  "trash .",
  // Filtered finds remove what the filters select, not the tree.
  "find . -name '*.pyc' -delete",
  "find . -type d -empty -delete",
  "find . -name .DS_Store -delete",
  "find . ! -path './keep/*' -mtime +30 -delete",
  // Targeted teardowns and named single resources: a person may approve them.
  "terraform destroy -target=aws_instance.web",
  "terraform destroy -target aws_instance.web -auto-approve",
  "pulumi destroy --target urn:pulumi:dev::app::aws:s3/bucket:Bucket::logs",
  "docker volume rm pgdata",
  "aws s3 rm s3://prod-data --recursive --exclude '*' --include 'tmp/*'",
  // A resource name that happens to be a kind word.
  "kubectl delete configmap project",
  "kubectl delete deployment ns -n prod",
  "terraform destroy -h",
  "git push --force origin release-notes",
  "docker compose down",
];

describe("FW-CATASTROPHIC: denied in every session", () => {
  for (const cmd of CATASTROPHIC) {
    it(cmd, () => {
      for (const o of [{}, { tainted: true }, { ctx: { interactive: false } }]) {
        const d = bash(cmd, o);
        expect(d.verdict, `${JSON.stringify(o)} ${explain(d)}`).toBe("deny");
        expect(d.rules, explain(d)).toContain("FW-CATASTROPHIC");
      }
    });
  }
});

describe("near misses stay approvable (never FW-CATASTROPHIC)", () => {
  for (const cmd of NEAR_MISSES) {
    it(cmd, () => {
      const d = bash(cmd);
      expect(d.verdict, explain(d)).not.toBe("deny");
      expect(d.findings.map((f) => f.id), explain(d)).not.toContain("catastrophic");
    });
  }
  it("deleting the home directory or the root stays FW-DESTROY-ROOT, now with the same plain explanation", () => {
    for (const cmd of ["rm -rf ~", "rm -rf /", `rm -rf ${HOME}/*`]) {
      const d = bash(cmd);
      expect(d.verdict, explain(d)).toBe("deny");
      expect(d.rules).toContain("FW-DESTROY-ROOT");
      expect(d.reasons.join(" ")).toMatch(/cannot be undone/);
    }
  });
});

/**
 * The catastrophic messages send a person to preview a teardown (terraform plan -destroy, pulumi preview
 * --destroy). The preview changes nothing, so it is judged as a plain plan is. Saved to a file it is the
 * first half of a teardown: applying a saved plan (terraform apply FILE) takes no destroy flag, so nothing at
 * the apply says destroy, and the firewall cannot read what a plan file holds. Saving it is what asks.
 */
describe("a teardown preview is allowed, a saved one is asked", () => {
  const SESSIONS: [string, RunOpts][] = [
    ["trusted", {}],
    ["after outside content", { tainted: true }],
    ["unattended", { ctx: { interactive: false } }],
  ];
  const PREVIEWS = [
    "terraform plan -destroy",
    "terraform plan --destroy",
    "terraform plan -destroy=true",
    "terraform plan -destroy -target=aws_instance.web",
    "terraform plan -destroy -var env=staging -var-file=staging.tfvars -no-color",
    "terraform plan -destroy -detailed-exitcode -lock=false",
    "terraform -chdir=infra plan -destroy",
    "cd infra && terraform plan -destroy",
    "timeout 600 terraform plan -destroy",
    "tofu plan -destroy",
    "tofu -chdir=infra plan -destroy",
    "terragrunt plan -destroy",
    "terragrunt plan-all -destroy",
    "terragrunt run-all plan -destroy",
    "terragrunt run --all plan -destroy",
    "terragrunt run --all -- plan -destroy",
    "pulumi preview --destroy",
  ];
  const SAVED = [
    "terraform plan -destroy -out=tf.plan",
    "terraform plan -destroy -out tf.plan",
    "terraform plan -destroy --out=tf.plan",
    "terraform plan -out=tf.plan -destroy",
    "terraform plan -destroy -target=aws_instance.web -out=tf.plan",
    "terraform -chdir=infra plan -destroy -out=tf.plan",
    "cd infra && terraform plan -destroy -out=tf.plan",
    "tofu plan -destroy -out=tf.plan",
    "tofu -chdir=infra plan -destroy -out=tf.plan",
    "terragrunt plan -destroy -out=tf.plan",
    "terragrunt plan-all -destroy -out=tf.plan",
    "terragrunt run-all plan -destroy -out=tf.plan",
    "terragrunt run --all plan -destroy -out=tf.plan",
    "pulumi preview --destroy --save-plan=plan.json",
    "pulumi preview --destroy --save-plan plan.json",
    // The flag with a value is the flag.
    "terraform plan -destroy=true -out=tf.plan",
    "tofu plan --destroy=true -out=tf.plan",
    "pulumi preview --destroy=true --save-plan=plan.json",
    // terragrunt saves a plan file for each module through its own plan directory, not through -out.
    "terragrunt run-all plan -destroy --terragrunt-out-dir plans",
    "terragrunt run-all plan -destroy --terragrunt-out-dir=plans",
    "terragrunt --terragrunt-out-dir=plans run-all plan -destroy",
    "terragrunt run --all plan -destroy --out-dir plans",
    "terragrunt plan -destroy --out-dir=plans",
    "terragrunt run-all plan -destroy --terragrunt-json-out-dir plans",
    "terragrunt run --all plan -destroy --json-out-dir plans",
    // Saved and applied in one line: the save is what the person is asked about.
    "terraform plan -destroy -out=tf.plan && terraform apply tf.plan",
    "tofu plan -destroy -out=tf.plan; tofu apply tf.plan",
  ];
  /** Teardowns that stay denied: a preview earlier in the line does not turn what follows into one. */
  const TEARDOWNS = [
    "terraform destroy",
    "terraform destroy -auto-approve",
    "terraform apply -destroy",
    "terraform apply -destroy -auto-approve",
    "terraform apply -auto-approve -destroy",
    "terraform apply --destroy",
    "terraform -chdir=infra apply -destroy -auto-approve",
    "tofu destroy -auto-approve",
    "tofu apply -destroy -auto-approve",
    "terragrunt destroy -auto-approve",
    "terragrunt destroy-all",
    "terragrunt destroy-all -auto-approve",
    "terragrunt apply -destroy -auto-approve",
    "terragrunt apply-all -destroy",
    "terragrunt run-all destroy",
    "terragrunt run-all apply -destroy",
    "terragrunt run --all destroy",
    "pulumi destroy --yes",
    "pulumi up --destroy --yes",
    "terraform plan -destroy && terraform destroy -auto-approve",
    "terraform plan -destroy; terraform apply -destroy -auto-approve",
    "tofu plan -destroy -out=tf.plan && tofu apply -destroy -auto-approve",
  ];

  for (const cmd of PREVIEWS) {
    it(`${cmd}: allowed in every session, and the session still counts as having read the account`, () => {
      for (const [label, o] of SESSIONS) {
        const d = bash(cmd, o);
        expect(d.verdict, `${label}: ${explain(d)}`).toBe("allow");
        expect(d.rules, `${label}: ${explain(d)}`).toEqual([]);
        expect(d.findings.map((f) => f.id), `${label}: ${explain(d)}`).not.toContain("catastrophic");
        // Like terraform plan, it contacts the provider and sees private state.
        expect(d.effects.some((e) => e.cls === "read_external" && e.private === true), `${label}: ${explain(d)}`).toBe(true);
        expect(d.verdict, label).toBe(bash("terraform plan", o).verdict);
      }
    });
  }

  for (const cmd of SAVED) {
    it(`${cmd}: asked (held when unattended), never denied`, () => {
      for (const [label, o] of SESSIONS) {
        const d = bash(cmd, o);
        expect(d.verdict, `${label}: ${explain(d)}`).toBe(o.ctx?.interactive === false ? "queue" : "ask");
        expect(d.rules, `${label}: ${explain(d)}`).toContain("FW-DESTRUCTIVE");
        expect(d.findings.map((f) => f.id), `${label}: ${explain(d)}`).not.toContain("catastrophic");
        expect(d.reasons.join(" "), label).toMatch(/saved plan file/);
      }
    });
  }

  it("the reason for a saved preview says what the file does", () => {
    const reason = bash("terraform plan -destroy -out=tf.plan").reasons.join(" ");
    expect(reason).toMatch(/saved plan file writes a plan that deletes every resource/);
    expect(reason).toMatch(/applying that file later carries no destroy flag/);
  });

  it("saving a plan that destroys nothing is still an ordinary plan", () => {
    for (const cmd of ["terraform plan -out=tf.plan", "terraform plan -out tf.plan -target=aws_instance.web", "tofu plan -out=tf.plan", "terragrunt run-all plan -out=tf.plan", "pulumi preview --save-plan=plan.json"]) {
      for (const [label, o] of SESSIONS) {
        const d = bash(cmd, o);
        expect(d.verdict, `${cmd} ${label}: ${explain(d)}`).toBe("allow");
        expect(d.rules, `${cmd} ${label}`).toEqual([]);
      }
    }
  });

  for (const cmd of TEARDOWNS) {
    it(`${cmd}: still denied in every session`, () => {
      for (const [label, o] of SESSIONS) {
        const d = bash(cmd, o);
        expect(d.verdict, `${label}: ${explain(d)}`).toBe("deny");
        expect(d.rules, `${label}: ${explain(d)}`).toContain("FW-CATASTROPHIC");
      }
    });
  }

  it("a targeted teardown stays an ordinary ask", () => {
    for (const cmd of ["terraform destroy -target=aws_instance.web", "terraform apply -destroy -target=aws_instance.web", "tofu destroy -target=aws_instance.web", "terragrunt destroy -target=aws_instance.web", "terragrunt destroy-all -target=aws_instance.web", "terragrunt apply-all -destroy -target=aws_instance.web", "pulumi destroy --target urn:pulumi:dev::app::aws:s3/bucket:Bucket::logs"]) {
      const d = bash(cmd);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(d.rules, cmd).toContain("FW-DESTRUCTIVE");
    }
  });

  it("a command whose verb it cannot read, carrying the flag, stays asked: a wrong guess asks, it never allows", () => {
    for (const cmd of ["terragrunt --terragrunt-working-dir infra plan -destroy", "terragrunt run --queue-include-dir ../vpc plan -destroy", "pulumi --stack dev preview --destroy"]) {
      const d = bash(cmd);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(d.rules, cmd).toContain("FW-DESTRUCTIVE");
    }
  });

  // Why the save is gated and not the apply: an apply of a saved plan is judged as every apply is. In a
  // trusted session a person has handed the agent the deploy (terraform apply -auto-approve is allowed too,
  // DEV-041 asks only after outside content); after outside content it is a send. Gating applies of a saved
  // plan alone would ask more of the reviewed way to apply than of -auto-approve.
  it("applying a saved plan is judged like any apply: allowed in a trusted session, asked after outside content", () => {
    for (const cmd of ["terraform apply tf.plan", "terraform apply -auto-approve tf.plan", "tofu apply tf.plan", "terragrunt apply tf.plan", "terragrunt apply-all", "terragrunt run-all apply", "terragrunt run --all apply", "pulumi up --plan plan.json --yes"]) {
      const trusted = bash(cmd);
      expect(trusted.verdict, `${cmd}: ${explain(trusted)}`).toBe("allow");
      const tainted = bash(cmd, { tainted: true });
      expect(tainted.verdict, `${cmd}: ${explain(tainted)}`).toBe("ask");
      expect(tainted.rules, cmd).toContain("FW-SEND");
      expect(bash(cmd, { tainted: true, ctx: { interactive: false } }).verdict, cmd).toBe("queue");
    }
    expect(bash("terraform apply -auto-approve").verdict).toBe("allow");
    expect(bash("terraform apply -auto-approve", { tainted: true }).rules).toContain("FW-SEND");
  });

  it("TF_CLI_ARGS and TF_CLI_ARGS_<name> set in the command can carry any option, so the command is asked in any session", () => {
    for (const cmd of [
      'TF_CLI_ARGS="-destroy -auto-approve" terraform apply',
      'TF_CLI_ARGS_plan="-destroy -out=tf.plan" terraform plan',
      'TF_CLI_ARGS_apply="-destroy" tofu apply',
      'env TF_CLI_ARGS="-destroy" terragrunt plan',
      'export TF_CLI_ARGS_plan="-out=tf.plan"',
    ]) {
      const d = bash(cmd);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      expect(d.rules, cmd).toContain("FW-UNCLASSIFIABLE");
    }
  });

  it("terragrunt's plan directory before the subcommand, or set in the environment, never makes a plain preview", () => {
    // Before the subcommand, the directory may be read as the subcommand: a teardown, asked.
    for (const cmd of ["terragrunt run --all --out-dir plans -- plan -destroy", "terragrunt run-all --terragrunt-out-dir plans plan -destroy"]) {
      for (const [label, o] of SESSIONS) {
        const d = bash(cmd, o);
        expect(d.verdict, `${cmd} ${label}: ${explain(d)}`).toBe(o.ctx?.interactive === false ? "queue" : "ask");
        expect(d.rules, `${cmd} ${label}`).toContain("FW-DESTRUCTIVE");
        expect(d.findings.map((f) => f.id), `${cmd} ${label}`).not.toContain("catastrophic");
      }
    }
    // Set in the environment it is an option the command does not show, as TF_CLI_ARGS is.
    for (const cmd of ["TG_OUT_DIR=plans terragrunt run-all plan -destroy", "TERRAGRUNT_OUT_DIR=plans terragrunt run-all plan -destroy", "env TG_JSON_OUT_DIR=plans terragrunt run --all plan -destroy", "export TERRAGRUNT_JSON_OUT_DIR=plans"]) {
      for (const [label, o] of SESSIONS) {
        const d = bash(cmd, o);
        expect(d.verdict, `${cmd} ${label}: ${explain(d)}`).toBe(o.ctx?.interactive === false ? "queue" : "ask");
        expect(d.rules, `${cmd} ${label}`).toContain("FW-UNCLASSIFIABLE");
      }
    }
  });

  it("a pulumi root option's value is not read as the subcommand, so a teardown after one stays denied", () => {
    for (const cmd of [
      "pulumi --profiling preview up --destroy --yes",
      "pulumi --tracing preview up --destroy --yes",
      "pulumi --tracing-header preview up --destroy --yes",
      "pulumi --color never up --destroy --yes",
      "pulumi -v 9 up --destroy --yes",
      "pulumi --verbose 9 up --destroy --yes",
      "pulumi --memprofilerate 1 up --destroy --yes",
    ]) {
      for (const [label, o] of SESSIONS) {
        const d = bash(cmd, o);
        expect(d.verdict, `${cmd} ${label}: ${explain(d)}`).toBe("deny");
        expect(d.rules, `${cmd} ${label}`).toContain("FW-CATASTROPHIC");
      }
    }
    // The shell analyzer does not take the value for the preview verb either: its own reading is a teardown.
    const d = bash("pulumi --profiling preview up --destroy --yes");
    expect(d.effects.some((e) => e.cls === "destructive" && e.detail === "pulumi destroy: delete infrastructure"), explain(d)).toBe(true);
  });

  it("the shell analyzer reads the teardown itself: destroy-all, a wrapped destroy, and destroy after an option's value", () => {
    for (const [cmd, tool] of [
      ["terragrunt destroy-all -target=aws_instance.web", "terragrunt"],
      ["terragrunt run-all destroy -target=aws_instance.web", "terragrunt"],
      ["terragrunt run --all destroy -target=aws_instance.web", "terragrunt"],
      ["pulumi --stack dev destroy --target urn:pulumi:dev::app::aws:s3/bucket:Bucket::logs", "pulumi"],
    ] as const) {
      const d = bash(cmd);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("ask");
      // The analyzer's own reading, beside the table's targeted-teardown question.
      expect(d.effects.some((e) => e.cls === "destructive" && e.detail === `${tool} destroy: delete infrastructure`), `${cmd}: ${explain(d)}`).toBe(true);
    }
  });
});

/**
 * Options that take a value can come before the subcommand (pulumi -C infra up, terragrunt --working-dir infra
 * apply, serverless --stage prod remove). The value is not the subcommand: the tables skip the values of the
 * options they know, and the shell analyzer, when a word may be an option's value, reads every word after it.
 */
describe("an option's value is not the subcommand", () => {
  it("an apply after an option's value is judged as an apply: allowed in a trusted session, asked after outside content", () => {
    for (const cmd of [
      "pulumi -C infra up --yes",
      "pulumi --cwd infra up --yes",
      "pulumi --stack prod up --yes",
      "pulumi --profiling preview up --yes",
      "terragrunt --terragrunt-working-dir infra apply",
      "terragrunt --working-dir infra run-all apply",
      "terragrunt run-all --terragrunt-working-dir infra apply",
      "terragrunt --terragrunt-working-dir infra apply-all",
      "terragrunt run --working-dir infra --all apply",
      "cdk --profile prod deploy",
      "serverless --stage prod deploy",
    ]) {
      const trusted = bash(cmd);
      expect(trusted.verdict, `${cmd}: ${explain(trusted)}`).toBe("allow");
      const tainted = bash(cmd, { tainted: true });
      expect(tainted.verdict, `${cmd}: ${explain(tainted)}`).toBe("ask");
      expect(tainted.rules, cmd).toContain("FW-SEND");
      expect(bash(cmd, { tainted: true, ctx: { interactive: false } }).verdict, cmd).toBe("queue");
    }
  });

  it("a read after an option's value stays a read, allowed after outside content", () => {
    for (const cmd of ["pulumi -C infra preview", "pulumi --stack dev stack output", "terragrunt --terragrunt-working-dir infra plan", "terragrunt run-all --terragrunt-working-dir infra output"]) {
      const d = bash(cmd, { tainted: true });
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("allow");
      expect(d.rules, cmd).toEqual([]);
    }
  });

  it("service logs read after an option's value are still outside content: the session becomes untrusted", () => {
    for (const cmd of ["pulumi -C infra logs", "pulumi --cwd infra logs --follow", "serverless --stage prod logs -f api", "sls -s prod logs -f api"]) {
      const d = bash(cmd);
      expect(d.verdict, `${cmd}: ${explain(d)}`).toBe("allow");
      expect(d.events.some((e) => e.type === "taint"), `${cmd}: ${explain(d)}`).toBe(true);
    }
    // The near miss: a read that is not logs leaves the session as it was.
    expect(bash("pulumi -C infra preview").events.some((e) => e.type === "taint")).toBe(false);
  });

  it("a serverless option's value is not read as the command, so remove after one stays denied", () => {
    for (const cmd of [
      "serverless --stage prod remove",
      "sls -s prod remove",
      "serverless --region us-east-1 remove",
      "sls -r eu-west-1 remove",
      "sls --aws-profile prod remove",
      "serverless -c serverless.prod.yml remove",
      "serverless --config serverless.prod.yml remove",
      "serverless --app shop remove",
      "sls --org acme remove",
      "sls --param key=value remove",
    ]) {
      for (const o of [{}, { tainted: true }, { ctx: { interactive: false } }]) {
        const d = bash(cmd, o);
        expect(d.verdict, `${cmd} ${JSON.stringify(o)}: ${explain(d)}`).toBe("deny");
        expect(d.rules, cmd).toContain("FW-CATASTROPHIC");
      }
    }
    const deploy = bash("serverless --stage prod deploy");
    expect(deploy.findings.map((f) => f.id), explain(deploy)).not.toContain("catastrophic");
  });
});

describe("MCP database tools", () => {
  const sql = (query: string) => run("mcp__supabase__execute_sql", { query });
  it("DROP DATABASE and TRUNCATE through an MCP SQL tool are denied", () => {
    for (const q of ["drop database postgres", "select 1; DROP SCHEMA public CASCADE"]) {
      const d = sql(q);
      expect(d.verdict, explain(d)).toBe("deny");
      expect(d.rules).toContain("FW-CATASTROPHIC");
    }
  });
  it("TRUNCATE through an MCP SQL tool is an ordinary destructive ask", () => {
    const d = sql("TRUNCATE TABLE users");
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-DESTRUCTIVE");
  });
  it("tools whose names delete a whole project, repository, database or namespace are denied", () => {
    for (const [tool, input] of [["mcp__github__delete_repository", { owner: "acme", repo: "app" }], ["mcp__supabase__delete_project", { id: "p1" }], ["mcp__neon__deleteDatabase", { name: "db" }], ["mcp__k8s__delete_namespace", { name: "prod" }], ["mcp__db__drop_table", { table: "users" }]] as const) {
      const d = run(tool, input);
      expect(d.verdict, `${tool}: ${explain(d)}`).toBe("deny");
      expect(d.rules).toContain("FW-CATASTROPHIC");
    }
    expect(run("mcp__github__delete_issue_comment", { id: 1 }).verdict).not.toBe("deny");
  });
  it("dropping one table stays FW-DESTRUCTIVE", () => {
    const d = sql("drop table audit");
    expect(d.verdict, explain(d)).toBe("ask");
    expect(d.rules).toContain("FW-DESTRUCTIVE");
  });
  it("a policy that calls the tool a read tool does not change it", () => {
    const config = { mcpServers: { supabase: { results: "trusted" as const, privateData: false, readTools: ["execute_sql"] } } };
    const d = run("mcp__supabase__execute_sql", { query: "drop database postgres" }, { config });
    expect(d.verdict, explain(d)).toBe("deny");
  });
});

describe("the reasons are plain and say what to do instead", () => {
  const cases: [string, RegExp][] = [
    ["terraform destroy", /plan -destroy/],
    ["git push --force origin main", /new branch and open a pull request/],
    ["dropdb app", /Back it up first/],
    ["kubectl delete ns prod", /Delete only the resources you no longer need/],
    ["docker volume prune -f", /docker rm NAME/],
    ["aws s3 rb s3://prod-data", /snapshot or a copy/],
    ["rm -rf .", /node_modules or dist/],
  ];
  for (const [cmd, instead] of cases) {
    it(cmd, () => {
      const reason = bash(cmd).reasons.join(" ");
      expect(reason).toMatch(/cannot be undone/);
      expect(reason).toMatch(/permission modes of Claude Code, Codex and Gemini CLI/);
      expect(reason).toMatch(instead);
    });
  }
  it("the rule is documented as deny, not approvable, with no policy key", () => {
    const r = RULES["FW-CATASTROPHIC"];
    expect(r?.approvable).toBe(false);
    expect(r?.outcome).toEqual({ trusted: "deny", untrusted: "deny" });
    expect(r?.policyKeys).toEqual([]);
  });
  it("the catalogue's examples for FW-DESTRUCTIVE and FW-CATASTROPHIC give the verdict they state", () => {
    for (const id of ["FW-DESTRUCTIVE", "FW-CATASTROPHIC"]) {
      const examples = RULES[id]?.examples ?? [];
      expect(examples.length, id).toBeGreaterThan(0);
      for (const ex of examples) {
        const sessions: RunOpts[] = ex.state === "any" ? [{}, { tainted: true }, { ctx: { interactive: false } }] : ex.state === "trusted" ? [{}] : [];
        expect(sessions.length, `${id}: ${ex.action} (${ex.state})`).toBeGreaterThan(0);
        for (const o of sessions) {
          const d = bash(ex.action, o);
          expect(d.verdict, `${id}: ${ex.action} ${JSON.stringify(o)}: ${explain(d)}`).toBe(ex.verdict);
          expect(d.rules, `${id}: ${ex.action}`).toContain(id);
        }
      }
    }
  });
});

describe("never downgraded", () => {
  const cmd = "terraform destroy -auto-approve";
  it("an approval for the exact action does not let it run", () => {
    const hash = actionHash({ tool: "Bash", input: { command: cmd } });
    const d = bash(cmd, { events: [{ type: "approval", actionHash: hash, id: "q1" }] });
    expect(d.verdict, explain(d)).toBe("deny");
    expect(d.rules).not.toContain("FW-APPROVED");
  });
  it("the loosest user policy does not change it", () => {
    const loose = { ...defaultConfig(), sendAllowHosts: ["*"], fetchAllowHosts: ["*"], dataAllowHosts: { credential: ["*"], card: ["*"], iban: ["*"], national_id: ["*"] }, unattendedPermissionModes: [], allowInstructionWritesWhenTrusted: true, allowTestValues: true, trustedReadRoots: ["/"] };
    for (const c of [cmd, "git push --force origin main", 'psql -c "DROP DATABASE app"', "kubectl delete ns prod"]) {
      const d = bash(c, { config: loose });
      expect(d.verdict, explain(d)).toBe("deny");
    }
  });
  it("a project policy may only tighten: its loosening keys are ignored and the verdict stays deny", () => {
    const doc = validatePolicy({ version: 3, sendAllowHosts: ["*"], fetchAllowHosts: ["*"], unattendedPermissionModes: [], allowInstructionWritesWhenTrusted: true }, "project");
    const { config } = mergeTighten(defaultConfig(), doc);
    expect(bash(cmd, { config }).verdict).toBe("deny");
  });
  it("the library: a host whose approval callback says yes to everything, in bypassPermissions mode, never gets asked", async () => {
    let asked = 0;
    const g = createGuard({ tools: { run_shell: { as: "Bash", input: (a) => ({ command: String(a.cmd) }) } }, workspace: WS, onApproval: () => { asked++; return true; } });
    for (const c of CATASTROPHIC.slice(0, 20)) {
      const a = await g.authorize({ tool: "run_shell", input: { cmd: c }, permissionMode: "bypassPermissions" });
      expect(a.decision.verdict, c).toBe("deny");
      expect(a.allowed, c).toBe(false);
    }
    expect(asked).toBe(0);
  });
});

describe("table units", () => {
  it("catastrophicCommand ignores tools it does not know and help output (--help, -h), not --version", () => {
    expect(catastrophicCommand("ls", ["-la"])).toBeNull();
    expect(catastrophicCommand("terraform", ["destroy", "--help"])).toBeNull();
    expect(catastrophicCommand("terraform", ["destroy", "-h"])).toBeNull();
    expect(catastrophicCommand("terraform", ["destroy", "--version"])).not.toBeNull();
    expect(catastrophicCommand("redis-cli", ["-h", "cache", "flushall"])).not.toBeNull();
    expect(catastrophicCommand("flyctl", ["volumes", "destroy", "v"])).not.toBeNull();
  });
  it("catastrophicPush reads value options and refspecs", () => {
    expect(catastrophicPush(["-o", "ci.skip", "origin", "main"])).toBeNull();
    expect(catastrophicPush(["-o", "n", "--force", "origin", "main"])).not.toBeNull();
    expect(catastrophicPush(["--force", "origin", "main"], { protectedBranches: [] })).not.toBeNull();
    expect(catastrophicPush(["--force", "origin", "develop"], { protectedBranches: [] })).toBeNull();
    expect(catastrophicPush(["--force", "origin", "staging"], { protectedBranches: ["staging"] })).not.toBeNull();
    expect(catastrophicPush(["--force", "-o", "main", "origin", "feature"])).toBeNull();
    expect(catastrophicPush(["--force", "origin", "feature:main"])).not.toBeNull();
    expect(catastrophicPush(["origin", "+feature:refs/heads/master"])).not.toBeNull();
  });
  it("catastrophicSql ignores DROP in a string literal and local TRUNCATE", () => {
    expect(catastrophicSql("select 'drop database x'", true)).toBeNull();
    expect(catastrophicSql("truncate users", false)).toBeNull();
    expect(catastrophicSql("/* x */ DROP DATABASE x", false)).not.toBeNull();
  });
});

/**
 * Each agent's bypass mode, through the real hook and that agent's own event format. Claude Code's
 * bypassPermissions reaches the hook as permission_mode and is attended by default; Codex's bypass flag and
 * `codex exec`, Gemini CLI's yolo and Cursor's --force are detected as unattended (the harness stands in for
 * the process check). The verdict is deny in every one, where an ordinary destructive action is asked or held.
 */
describe("bypass and yolo modes, per agent, through the hook", () => {
  let b: Box;
  beforeEach(() => {
    b = box();
  });
  afterEach(() => b.cleanup());

  const AGENTS: { agent: AgentId; mode?: string; unattended: boolean }[] = [
    { agent: "claude", mode: "bypassPermissions", unattended: false },
    { agent: "claude", mode: "dontAsk", unattended: false },
    { agent: "codex", mode: "bypassPermissions", unattended: true },
    { agent: "gemini", unattended: true },
    { agent: "cursor", unattended: true },
  ];
  const pre = (command: string, mode?: string) => ({ hook_event_name: "PreToolUse", session_id: "s1", cwd: b.ws, ...(mode !== undefined ? { permission_mode: mode } : {}), tool_name: "Bash", tool_input: { command } });

  for (const a of AGENTS) {
    it(`${a.agent}${a.mode !== undefined ? ` (${a.mode})` : " (yolo / force)"}`, () => {
      for (const cmd of ["terraform destroy -auto-approve", "git push --force origin main", "kubectl delete namespace prod", 'psql -c "DROP DATABASE app"', "docker system prune -af", `rm -rf ${b.ws}`]) {
        const ev = toNative(a.agent, pre(cmd, a.mode));
        expect(ev, cmd).not.toBeNull();
        const io = send(b, a.agent, ev as Record<string, unknown>, { unattended: a.unattended });
        expect(verdict(a.agent, io), `${cmd}: ${io.stdout}${io.stderr}`).toBe("deny");
        expect(rules(a.agent, io), cmd).toContain("FW-CATASTROPHIC");
      }
      // The contrast: an ordinary destructive action is asked (Claude Code) or held, not denied.
      const io = send(b, a.agent, toNative(a.agent, pre("kubectl delete pod web-1", a.mode)) as Record<string, unknown>, { unattended: a.unattended });
      expect(verdict(a.agent, io)).not.toBe("deny");
    });
  }

  it("the message tells the person why and to run it themselves", () => {
    const io = send(b, "claude", pre("terraform destroy", "bypassPermissions"));
    const out = JSON.parse(io.stdout) as { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/cannot be undone/);
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/run it yourself/);
  });
});

/**
 * Known gaps that need the shell parser or analyzer internals (src/engine/shell/), which this change does not
 * touch. Each is expected to fail until an engineer extends that layer; none is allowed silently except where
 * noted, and the near-equivalent literal command is denied above.
 */
describe("gaps left for the shell layer", () => {
  // Variable assignments earlier in the line are not carried into later words (allowed today).
  it.fails("a verb held in a shell variable: X=destroy; terraform $X", () => expect(bash("X=destroy; terraform $X").verdict).toBe("deny"));
  // SQL piped into a client on stdin from another stage is not read as the client's SQL (allowed today).
  it.fails('SQL piped from echo: echo "DROP DATABASE app" | psql', () => expect(bash('echo "DROP DATABASE app" | psql').verdict).toBe("deny"));
  // A command substitution's result is not known statically (asked today, as FW-UNCLASSIFIABLE and FW-DESTRUCTIVE).
  it.fails('the workspace named by a substitution: rm -rf "$(pwd)"', () => expect(bash('rm -rf "$(pwd)"').verdict).toBe("deny"));
  // Inline interpreter code that starts a program is opaque code, not that program (allowed in a trusted session today).
  it.fails("a program started from inline Python: subprocess.run(['terraform','destroy'])", () => expect(bash(`python3 -c "import subprocess; subprocess.run(['terraform','destroy'])"`).verdict).toBe("deny"));
});
