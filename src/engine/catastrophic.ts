/**
 * The catastrophic class: actions whose damage cannot be undone and that no coding task needs an agent
 * to do on its own. Deleting the home directory, the root or the whole workspace; force-pushing over a
 * protected branch; dropping a database; deleting cloud buckets, volumes, clusters, namespaces, projects
 * or accounts.
 *
 * Pure tables. The shell analyzer and the MCP classifier call them with the words they already resolved
 * (through wrappers, nested shells, npx and the like), and the engine denies a match (FW-CATASTROPHIC) in
 * every session, permission mode and policy, approval or not. The tables are narrow on purpose: deleting
 * one pod, one file, one row, one named volume or a targeted part of a stack stays an ordinary destructive
 * action that a person may approve. Two things turn a match into such an ask instead of a deny:
 *
 * - the target is named only at run time (a variable or a substitution), so the firewall cannot tell what
 *   it is (a literal catastrophic verb with a run-time target is still denied);
 * - every target is a name the person listed as scratch (the signed scratch-target allowlist, user level
 *   only: `launchsafe-firewall scratch add 'app_*_test'`), for the kinds of target that can be scratch
 *   (a database, a namespace, an app, a branch database, a bucket). Accounts, projects, clusters, database
 *   servers, the workspace and protected branches never can.
 */

import { sqlStatements, stripSql } from "./sql.js";
import { own } from "../own.js";

/** Branch names that are always protected, whatever the policy says. */
export const CORE_PROTECTED_BRANCHES: readonly string[] = ["main", "master", "trunk"];
/** The policy's default additions (protectedBranches); a person may change these. */
export const DEFAULT_PROTECTED_BRANCHES: readonly string[] = ["production", "prod", "develop", "release/*"];

/** The part every catastrophic reason shares: why it is blocked, not asked. */
const BLOCKED = "so the firewall blocks it in the permission modes of Claude Code, Codex and Gemini CLI (bypass, yolo and full-auto included) and it cannot be approved from inside the agent";
const NEVER = `it cannot be undone, ${BLOCKED}`;
/** For a command that only may do the damage (a disk tool also has read-only forms): the same block, said conditionally. */
const NEVER_IF = `if it does, that cannot be undone, ${BLOCKED}`;
/** A KMS key is unusable at once but destroyed only after its waiting period. */
const NEVER_KEY = `it makes the key unusable at once and the key is destroyed for good when the waiting period ends, ${BLOCKED}`;

const INSTEAD = {
  stack: "Preview or target part of it with your tool, or run it yourself after checking which stack and account it targets.",
  infra: "To see what it would remove, preview it first (terraform plan -destroy, pulumi preview --destroy); to remove part of it, target that part (terraform destroy -target=ADDRESS), which you can approve.",
  storage: "Take a snapshot or a copy first. To clean up, have the agent delete only the files or objects you name.",
  cluster: "Delete only the resources you no longer need (a deployment, a pod, one service), or run it yourself after checking which account, project or context it targets.",
  database: "Back it up first (pg_dump, mysqldump, mongodump) and run it yourself. To clear test data, delete the rows you want gone with a WHERE clause.",
  databaseScratch: "Back it up first (pg_dump, mysqldump, mongodump) and run it yourself. To clear test data, delete the rows you want gone with a WHERE clause. For a throwaway database, a person can list its name pattern as scratch (launchsafe-firewall scratch add), which makes this a question instead.",
  docker: "Remove specific containers, images or one named volume instead (docker rm NAME, docker image prune, docker volume rm NAME). Volumes hold databases and other data that cannot be rebuilt.",
  git: "Push to a new branch and open a pull request instead. If the protected branch really must be rewritten, do it yourself.",
  history: "Leave the reflog as it is: it is what lets you recover lost commits. If you really want it pruned, run it yourself.",
  repo: "Archive the repository instead (gh repo archive), or delete it yourself in the hosting site's settings.",
  key: "The key becomes unusable at once and is destroyed after the waiting period (7 to 30 days); cancel with aws kms cancel-key-deletion before then. Disable it instead (aws kms disable-key).",
  workspace: "Delete the specific files or build folders instead (for example node_modules or dist).",
  root: "Delete the specific files or folders you mean instead.",
  disk: "Work on files instead. Erasing, formatting or writing over a disk device destroys everything on it; if that is really meant, do it yourself.",
  diskTool: "Work on files instead. Disk and partition tools can erase, format or write over a disk device, which destroys everything on it; if that is really meant, do it yourself.",
} as const;

export type CatastropheKind = keyof typeof INSTEAD;

/** The plain-language reason a person and the agent see for a catastrophic action. */
export function catastropheReason(what: string, kind: CatastropheKind): string {
  const never = kind === "diskTool" ? NEVER_IF : kind === "key" ? NEVER_KEY : NEVER;
  return `${what}: ${never}. ${INSTEAD[kind]}`;
}

/** A word of a command: its quote-removed text, and whether its value is only known at run time. */
export interface CmdWord {
  text: string;
  dynamic: boolean;
}

/** What the firewall says about a command: deny it (FW-CATASTROPHIC), or ask as an ordinary destructive action. */
export interface Judgement {
  level: "deny" | "ask";
  reason: string;
}

export interface CatastropheOptions {
  /** Scratch-target name patterns from the signed user-level allowlist (absent: none). */
  scratch?: readonly string[];
  /** Branch patterns protected in addition to main, master and trunk (the policy's protectedBranches). */
  protectedBranches?: readonly string[];
}

const deny = (what: string, kind: CatastropheKind): Judgement => ({ level: "deny", reason: catastropheReason(what, kind) });
const ask = (reason: string): Judgement => ({ level: "ask", reason });

/** `*` glob over a whole name, ignoring case (the words are compared lower-cased). */
export function globName(pattern: string, name: string): boolean {
  const re = new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");
  return re.test(name);
}

/** A valid scratch pattern: letters, digits, `_ . - *`, at least three characters that are not `*`. */
export function validScratchPattern(p: string): boolean {
  return /^[A-Za-z0-9_.*-]{1,100}$/.test(p) && p.replace(/\*/g, "").length >= 3;
}

/** The scratch pattern every name matches, or null when one of them is not scratch (or there are none). */
function scratchFor(names: readonly CmdWord[], patterns: readonly string[] | undefined): string | null {
  if (patterns === undefined || patterns.length === 0 || names.length === 0) return null;
  let hit: string | null = null;
  for (const n of names) {
    if (n.dynamic || n.text === "") return null;
    const p = patterns.find((x) => validScratchPattern(x) && globName(x, n.text));
    if (p === undefined) return null;
    hit = p;
  }
  return hit;
}

function scratchAsk(what: string, names: readonly CmdWord[], pattern: string): Judgement {
  return ask(`${what} (${names.map((n) => n.text).join(", ")}): this cannot be undone, and the name matches your scratch-target pattern "${pattern}", so a person may approve it`);
}

// --- reading the words ---------------------------------------------------------------------------------

/** Options that take a value, per tool, so the value is not read as a subcommand or a target. */
const VALUE_OPTS: Readonly<Record<string, readonly string[]>> = {
  kubectl: ["-n", "--namespace", "--context", "--cluster", "--user", "-l", "--selector", "-f", "--filename", "-o", "--output", "--kubeconfig", "-s", "--server", "--field-selector", "-c", "--container", "--grace-period", "--timeout", "--cascade"],
  heroku: ["-a", "--app", "-r", "--remote", "--confirm", "-t", "--team"],
  fly: ["-a", "--app", "-c", "--config", "-r", "--region", "-t", "--access-token", "-o", "--org"],
  vercel: ["-S", "--scope", "-t", "--token", "--cwd", "-A", "--local-config", "-Q", "--global-config", "-T", "--team"],
  railway: ["-s", "--service", "-e", "--environment", "-p", "--project"],
  netlify: ["--site", "--auth", "--filter", "--context"],
  supabase: ["--project-ref", "--db-url", "--workdir", "-o", "--output", "--password", "-p"],
  dropdb: ["-h", "--host", "-p", "--port", "-U", "--username", "--maintenance-db"],
  mysqladmin: ["-h", "--host", "-u", "--user", "-P", "--port", "-S", "--socket"],
  "redis-cli": ["-h", "-p", "-a", "-n", "-u", "--user", "--pass", "-s"],
  gcloud: ["--project", "--zone", "--region", "--account", "--format", "--configuration", "--instance", "--location"],
  gh: ["-R", "--repo", "-X", "--method", "-H", "--header", "-f", "-F", "--field", "--raw-field", "--jq", "-q", "--input", "-p", "--preview", "--hostname", "-t", "--template"],
  docker: ["-f", "--file", "-p", "--project-name", "--context", "-H", "--host", "--project-directory", "--env-file", "--profile"],
  "docker-compose": ["-f", "--file", "-p", "--project-name", "--project-directory", "--env-file", "--profile", "-t", "--timeout"],
  terraform: ["-var", "-var-file", "-target", "-state", "-chdir", "-lock-timeout", "-parallelism"],
  // With pulumi's root options too: they may come before the subcommand (pulumi --profiling FILE up), and a
  // value read as the subcommand would hide the real one from `up`, which must be the first word.
  pulumi: ["-s", "--stack", "-C", "--cwd", "--target", "-t", "--config", "-c", "--config-file", "--color", "--profiling", "--tracing", "--tracing-header", "--memprofilerate", "-v", "--verbose"],
  // The Serverless Framework reads its service options before the command too (serverless --stage prod remove).
  serverless: ["-s", "--stage", "-r", "--region", "--aws-profile", "-c", "--config", "--app", "--org", "--param"],
  sls: ["-s", "--stage", "-r", "--region", "--aws-profile", "-c", "--config", "--app", "--org", "--param"],
  neonctl: ["--project-id", "--org-id", "-o", "--output"],
  pscale: ["--org"],
  git: ["-C", "-c", "--git-dir", "--work-tree", "--namespace"],
};

/** Tools whose -h names a host, not help. */
const H_IS_HOST = new Set(["redis-cli", "mysqladmin", "dropdb"]);

interface Pos {
  text: string;
  dynamic: boolean;
}

function positionals(tool: string, words: readonly CmdWord[]): Pos[] {
  const takes = new Set(own(VALUE_OPTS, tool) ?? []);
  const out: Pos[] = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as CmdWord;
    if (w.text === "--") {
      for (const x of words.slice(i + 1)) out.push({ text: x.text.toLowerCase(), dynamic: x.dynamic });
      break;
    }
    if (w.text.startsWith("-")) {
      if (takes.has(w.text)) i++;
      continue;
    }
    out.push({ text: w.text.toLowerCase(), dynamic: w.dynamic });
  }
  return out;
}

function hasFlag(args: readonly CmdWord[], ...names: string[]): boolean {
  return args.some((a) => names.includes(a.text) || names.some((n) => n.startsWith("-") && a.text.startsWith(`${n}=`)));
}

/** A short flag group (`-rf`) that contains the letter. */
function shortHas(args: readonly CmdWord[], letter: string): boolean {
  return args.some((a) => /^-[a-zA-Z]+$/.test(a.text) && a.text.includes(letter));
}

/** A storage URL naming a whole bucket (s3://bucket, gs://bucket/, gs://bucket/**), not a prefix inside it. */
function bucketRoot(pos: readonly Pos[], scheme: string): Pos | undefined {
  return pos.find((p) => new RegExp(`^${scheme}://[^/]+(?:/\\*{1,2})?/?$`).test(p.text));
}

const bucketName = (p: Pos): CmdWord => ({ text: p.text.replace(/^[a-z0-9]+:\/\//, "").replace(/\/(?:\*{1,2})?\/?$/, ""), dynamic: p.dynamic });

// --- the tables ----------------------------------------------------------------------------------------

interface Ctx {
  args: readonly CmdWord[];
  pos: readonly Pos[];
  /** The positionals after the matched path: the targets. */
  after: readonly Pos[];
}

interface Entry {
  path: readonly string[];
  /** The path must be the command's first positionals (single-word verbs that other subcommands also use). */
  first?: boolean;
  when?: (x: Ctx) => boolean;
  /** A matched command that is an ordinary destructive action after all (a targeted teardown): the ask reason. */
  demote?: (x: Ctx) => string | null;
  /** The names this deletes, for the scratch allowlist; absent: never scratch. */
  targets?: (x: Ctx) => CmdWord[];
  what: string;
  kind: CatastropheKind;
}

const e = (path: string, what: string, kind: CatastropheKind, more: Partial<Entry> = {}): Entry => ({ path: path.split(" "), what, kind, ...more });

const RECURSIVE = (x: Ctx): boolean => hasFlag(x.args, "--recursive", "-r", "-R") || shortHas(x.args, "r") || shortHas(x.args, "R");
const AFTER = (x: Ctx): CmdWord[] => x.after.map((p) => ({ text: p.text, dynamic: p.dynamic }));
const FIRST_AFTER = (x: Ctx): CmdWord[] => AFTER(x).slice(0, 1);

const AWS: readonly Entry[] = [
  e("s3 rb", "delete an S3 bucket", "storage", { targets: (x) => x.pos.filter((p) => p.text.startsWith("s3://")).map(bucketName) }),
  e("s3 rm", "delete everything in an S3 bucket", "storage", {
    when: (x) => RECURSIVE(x) && bucketRoot(x.pos, "s3") !== undefined,
    demote: (x) => (hasFlag(x.args, "--exclude", "--include") ? "aws s3 rm --recursive with --exclude/--include removes only the objects the filters select" : null),
    targets: (x) => x.pos.filter((p) => p.text.startsWith("s3://")).map(bucketName),
  }),
  e("s3api delete-bucket", "delete an S3 bucket", "storage"),
  e("s3api delete-objects", "delete objects from an S3 bucket in bulk", "storage"),
  e("s3api delete-object-versions", "delete object versions from an S3 bucket", "storage"),
  e("ec2 delete-volume", "delete an EBS volume", "storage"),
  e("efs delete-file-system", "delete an EFS file system", "storage"),
  e("fsx delete-file-system", "delete an FSx file system", "storage"),
  e("glacier delete-vault", "delete a Glacier vault", "storage"),
  e("backup delete-backup-vault", "delete a backup vault", "storage"),
  e("ecr delete-repository", "delete an ECR repository with every image in it", "storage", { when: (x) => hasFlag(x.args, "--force") }),
  e("kms schedule-key-deletion", "schedule a KMS key for deletion", "key"),
  e("route53 delete-hosted-zone", "delete a Route 53 hosted zone (a domain's DNS)", "cluster"),
  e("eks delete-cluster", "delete an EKS cluster", "cluster"),
  e("ecs delete-cluster", "delete an ECS cluster", "cluster"),
  e("emr terminate-clusters", "terminate EMR clusters", "cluster"),
  e("kafka delete-cluster", "delete an MSK cluster", "cluster"),
  e("redshift delete-cluster", "delete a Redshift cluster", "database"),
  e("rds delete-db-instance", "delete an RDS database", "database"),
  e("rds delete-db-cluster", "delete an RDS database cluster", "database"),
  e("rds delete-global-cluster", "delete a global RDS database cluster", "database"),
  e("docdb delete-db-cluster", "delete a DocumentDB cluster", "database"),
  e("neptune delete-db-cluster", "delete a Neptune cluster", "database"),
  e("dynamodb delete-table", "delete a DynamoDB table", "database"),
  e("elasticache delete-cache-cluster", "delete an ElastiCache cluster", "database"),
  e("elasticache delete-replication-group", "delete an ElastiCache replication group", "database"),
  e("opensearch delete-domain", "delete an OpenSearch domain", "database"),
  e("es delete-elasticsearch-domain", "delete an Elasticsearch domain", "database"),
  e("cloudformation delete-stack", "delete a CloudFormation stack and the resources it created", "stack"),
  e("organizations close-account", "close an AWS account", "cluster"),
];

const GCLOUD: readonly Entry[] = [
  e("projects delete", "delete a Google Cloud project", "cluster"),
  e("container clusters delete", "delete a GKE cluster", "cluster"),
  e("dataproc clusters delete", "delete a Dataproc cluster", "cluster"),
  e("compute disks delete", "delete Compute Engine disks", "storage"),
  e("filestore instances delete", "delete a Filestore instance", "storage"),
  e("storage buckets delete", "delete a Cloud Storage bucket", "storage", { targets: (x) => x.pos.filter((p) => p.text.startsWith("gs://")).map(bucketName) }),
  e("storage rm", "delete everything in a Cloud Storage bucket", "storage", { when: (x) => RECURSIVE(x) && bucketRoot(x.pos, "gs") !== undefined, targets: (x) => x.pos.filter((p) => p.text.startsWith("gs://")).map(bucketName) }),
  e("sql instances delete", "delete a Cloud SQL instance", "database"),
  e("sql databases delete", "delete a Cloud SQL database", "database", { targets: FIRST_AFTER }),
  e("alloydb clusters delete", "delete an AlloyDB cluster", "database"),
  e("spanner instances delete", "delete a Spanner instance", "database"),
  e("spanner databases delete", "delete a Spanner database", "database", { targets: FIRST_AFTER }),
  e("firestore databases delete", "delete a Firestore database", "database"),
  e("bigtable instances delete", "delete a Bigtable instance", "database"),
  e("redis instances delete", "delete a Memorystore instance", "database"),
];

const AZ: readonly Entry[] = [
  e("group delete", "delete an Azure resource group and everything in it", "cluster"),
  e("aks delete", "delete an AKS cluster", "cluster"),
  e("disk delete", "delete an Azure managed disk", "storage"),
  e("storage account delete", "delete an Azure storage account", "storage"),
  e("storage container delete", "delete an Azure storage container", "storage"),
  e("sql server delete", "delete an Azure SQL server", "database"),
  e("sql db delete", "delete an Azure SQL database", "database"),
  e("cosmosdb delete", "delete a Cosmos DB account", "database"),
  e("postgres flexible-server delete", "delete an Azure PostgreSQL server", "database"),
  e("postgres server delete", "delete an Azure PostgreSQL server", "database"),
  e("mysql flexible-server delete", "delete an Azure MySQL server", "database"),
  e("mysql server delete", "delete an Azure MySQL server", "database"),
  e("redis delete", "delete an Azure Cache for Redis", "database"),
];

const NS_KINDS = /^(?:ns|namespaces?|projects?)$/;
const VOLUME_KINDS = /^(?:pv|persistentvolumes?|pvc|persistentvolumeclaims?)$/;
const CRD_KINDS = /^(?:crds?|customresourcedefinitions?(?:\.apiextensions\.k8s\.io)?)$/;

/**
 * kubectl/oc delete: only the resource kind (the first word after `delete`, a comma list, or the kind of
 * each kind/name word) is compared, never a resource's name. Catastrophic: a namespace or an OpenShift
 * project (with everything in it), a persistent volume or its claim, a custom resource definition (with
 * every resource of that kind), `delete all --all`, and anything across all namespaces.
 */
function kubeDelete(tool: string, words: readonly CmdWord[], o: CatastropheOptions): Judgement | null {
  const pos = positionals(tool, words);
  const at = pos.findIndex((p) => p.text === "delete");
  if (at === -1) return null;
  const rest = pos.slice(at + 1);
  const first = rest[0];
  // A dry run deletes nothing (judgePush exempts it the same way).
  if (words.some((w) => /^--dry-run=(?:client|server|true)$/.test(w.text))) return null;
  if (hasFlag(words, "--all-namespaces", "-A")) return deny(`${tool} delete across all namespaces`, "cluster");
  if (first === undefined) return null;
  const slashed = rest.filter((p) => p.text.includes("/"));
  const kinds = first.text.includes("/") ? slashed.map((p) => p.text.split("/")[0] as string) : first.text.split(",");
  const names: CmdWord[] = first.text.includes("/") ? slashed.map((p) => ({ text: p.text.split("/").slice(1).join("/"), dynamic: p.dynamic })) : rest.slice(1).map((p) => ({ text: p.text, dynamic: p.dynamic }));
  if (first.dynamic && !first.text.includes("/")) return ask(`${tool} delete with a resource kind known only at run time (${first.text}): it could be a namespace or every resource of a kind`);
  if (kinds.includes("all") && hasFlag(words, "--all")) return deny(`${tool} delete all --all removes every resource in the namespace`, "cluster");
  if (kinds.some((k) => CRD_KINDS.test(k))) return deny(`${tool} delete of a custom resource definition removes every resource of that kind`, "cluster");
  if (kinds.some((k) => VOLUME_KINDS.test(k))) return deny(`${tool} delete of a persistent volume or volume claim deletes its data`, "storage");
  if (kinds.some((k) => NS_KINDS.test(k))) {
    const what = `${tool} delete of a namespace removes everything in it`;
    const onlyNs = kinds.every((k) => NS_KINDS.test(k));
    const pattern = onlyNs ? scratchFor(names, o.scratch) : null;
    return pattern !== null ? scratchAsk(what, names, pattern) : deny(what, "cluster");
  }
  return null;
}

/** `gh api -X DELETE repos/OWNER/REPO`: the repository itself, not something inside it. */
function ghApiDelete(words: readonly CmdWord[]): Judgement | null {
  let method = "";
  for (let i = 0; i < words.length; i++) {
    const t = (words[i] as CmdWord).text;
    if (t === "-X" || t === "--method") method = words[i + 1]?.text ?? "";
    else if (/^-X./.test(t)) method = t.slice(2);
    else if (t.startsWith("--method=")) method = t.slice(9);
  }
  if (method.toUpperCase() !== "DELETE") return null;
  const pos = positionals("gh", words);
  if (pos[0]?.text !== "api") return null;
  const endpoint = pos[1];
  if (endpoint === undefined) return null;
  if (endpoint.dynamic) return ask(`gh api DELETE on an endpoint known only at run time (${endpoint.text}): it could be a repository`);
  return /^\/?repos\/[^/]+\/[^/]+\/?$/.test(endpoint.text) ? deny(`gh api DELETE ${endpoint.text} deletes the repository`, "repo") : null;
}

const IAC_TARGET = (x: Ctx): string | null => (hasFlag(x.args, "-target", "--target") ? "a destroy limited with -target removes only the resources it names" : null);

const IAC_DESTROY = (name: string): Entry[] => [
  { path: ["destroy"], what: `${name} destroy deletes every resource this configuration manages`, kind: "infra", demote: IAC_TARGET },
  { path: ["apply"], when: (x) => hasFlag(x.args, "-destroy", "--destroy"), what: `${name} apply -destroy deletes every resource this configuration manages`, kind: "infra", demote: IAC_TARGET },
];

/** `vercel rm NAME` names a project (all its deployments); a deployment URL or id names one deployment. */
function wholeVercelProject(x: Ctx): boolean {
  return x.after.length > 0 && x.after.some((t) => t.dynamic || (!t.text.includes(".") && !t.text.startsWith("dpl_")));
}

const TABLES: Readonly<Record<string, readonly Entry[]>> = {
  aws: AWS,
  gcloud: GCLOUD,
  gsutil: [
    e("rb", "delete a Cloud Storage bucket", "storage", { first: true, targets: (x) => x.after.filter((p) => p.text.startsWith("gs://")).map(bucketName) }),
    e("rm", "delete everything in a Cloud Storage bucket", "storage", { first: true, when: (x) => RECURSIVE(x) && bucketRoot(x.pos, "gs") !== undefined }),
  ],
  bq: [e("rm", "delete a BigQuery dataset with its tables", "database", { first: true, when: (x) => hasFlag(x.args, "-d", "--dataset", "-r", "--recursive") || shortHas(x.args, "d") || shortHas(x.args, "r") })],
  az: AZ,
  eksctl: [e("delete cluster", "delete an EKS cluster", "cluster")],
  doctl: [
    e("kubernetes cluster delete", "delete a DigitalOcean Kubernetes cluster", "cluster"),
    e("k8s cluster delete", "delete a DigitalOcean Kubernetes cluster", "cluster"),
    e("projects delete", "delete a DigitalOcean project", "cluster"),
    e("databases delete", "delete a DigitalOcean database cluster", "database"),
    e("compute volume delete", "delete a DigitalOcean volume", "storage"),
  ],
  terraform: IAC_DESTROY("terraform"),
  tofu: IAC_DESTROY("tofu"),
  terragrunt: [
    ...IAC_DESTROY("terragrunt"),
    // The deprecated spellings older Terragrunt still accepts.
    { path: ["destroy-all"], what: "terragrunt destroy-all deletes every resource this configuration manages", kind: "infra", demote: IAC_TARGET },
    { path: ["apply-all"], when: (x) => hasFlag(x.args, "-destroy", "--destroy"), what: "terragrunt apply-all -destroy deletes every resource this configuration manages", kind: "infra", demote: IAC_TARGET },
  ],
  pulumi: [...IAC_DESTROY("pulumi"), e("up", "pulumi up --destroy deletes every resource in the stack", "infra", { first: true, when: (x) => hasFlag(x.args, "--destroy"), demote: IAC_TARGET }), e("stack rm", "remove a Pulumi stack and its history", "stack")],
  cdk: [e("destroy", "cdk destroy deletes every resource in the stack", "stack")],
  sam: [e("delete", "sam delete deletes the stack and its resources", "stack", { first: true })],
  serverless: [e("remove", "serverless remove deletes the service and its resources", "stack", { first: true })],
  sls: [e("remove", "serverless remove deletes the service and its resources", "stack", { first: true })],
  railway: [
    e("delete", "delete a Railway project", "cluster", { first: true }),
    e("volume delete", "delete a Railway volume", "storage"),
    e("environment delete", "delete a Railway environment", "cluster", { targets: FIRST_AFTER }),
  ],
  fly: [
    e("destroy", "destroy a Fly.io app", "cluster", { first: true, targets: FIRST_AFTER }),
    e("apps destroy", "destroy a Fly.io app", "cluster", { targets: FIRST_AFTER }),
    e("apps delete", "destroy a Fly.io app", "cluster", { targets: FIRST_AFTER }),
    // flyctl accepts app, vol and volume as the singular or short spellings of apps and volumes (verify against a current flyctl).
    e("app destroy", "destroy a Fly.io app", "cluster", { targets: FIRST_AFTER }),
    e("app delete", "destroy a Fly.io app", "cluster", { targets: FIRST_AFTER }),
    e("vol destroy", "destroy a Fly.io volume", "storage"),
    e("vol delete", "destroy a Fly.io volume", "storage"),
    e("volumes destroy", "destroy a Fly.io volume", "storage"),
    e("volumes delete", "destroy a Fly.io volume", "storage"),
    e("volume destroy", "destroy a Fly.io volume", "storage"),
    e("volume delete", "destroy a Fly.io volume", "storage"),
  ],
  vercel: [
    e("remove", "remove every deployment of a Vercel project", "cluster", { first: true, when: wholeVercelProject, targets: AFTER }),
    e("rm", "remove every deployment of a Vercel project", "cluster", { first: true, when: wholeVercelProject, targets: AFTER }),
    e("project rm", "delete a Vercel project", "cluster", { targets: FIRST_AFTER }),
    e("project remove", "delete a Vercel project", "cluster", { targets: FIRST_AFTER }),
    e("projects rm", "delete a Vercel project", "cluster", { targets: FIRST_AFTER }),
    e("projects remove", "delete a Vercel project", "cluster", { targets: FIRST_AFTER }),
  ],
  supabase: [
    e("projects delete", "delete a Supabase project", "cluster"),
    e("branches delete", "delete a Supabase branch and its database", "database", { targets: FIRST_AFTER }),
    e("db reset", "reset a remote Supabase database", "database", { when: (x) => hasFlag(x.args, "--linked", "--db-url") }),
  ],
  heroku: [
    e("apps:destroy", "destroy a Heroku app", "cluster", { first: true, targets: (x) => herokuApp(x) }),
    e("destroy", "destroy a Heroku app", "cluster", { first: true, targets: (x) => herokuApp(x) }),
    e("addons:destroy", "destroy a Heroku add-on (a database is one)", "database", { first: true }),
    e("pg:reset", "erase a Heroku Postgres database", "database", { first: true }),
  ],
  netlify: [e("sites:delete", "delete a Netlify site", "cluster", { first: true })],
  neonctl: [e("projects delete", "delete a Neon project", "database"), e("databases delete", "delete a Neon database", "database", { targets: FIRST_AFTER })],
  pscale: [e("database delete", "delete a PlanetScale database", "database", { targets: FIRST_AFTER })],
  planetscale: [e("database delete", "delete a PlanetScale database", "database", { targets: FIRST_AFTER })],
  turso: [e("db destroy", "destroy a Turso database", "database", { targets: FIRST_AFTER })],
  docker: [
    e("volume prune", "delete every unused Docker volume", "docker"),
    e("system prune", "remove all unused Docker data", "docker"),
    e("compose down", "docker compose down -v deletes the project's volumes", "docker", { when: (x) => hasFlag(x.args, "-v", "--volumes") || shortHas(x.args, "v") }),
  ],
  "docker-compose": [e("down", "docker-compose down -v deletes the project's volumes", "docker", { first: true, when: (x) => hasFlag(x.args, "-v", "--volumes") || shortHas(x.args, "v") })],
  dropdb: [{ path: [], what: "drop a whole PostgreSQL database (dropdb)", kind: "database", targets: AFTER }],
  mysqladmin: [e("drop", "drop a whole MySQL database (mysqladmin drop)", "database", { targets: AFTER })],
  "redis-cli": [
    e("flushall", "erase every key in every Redis database (FLUSHALL)", "database"),
    e("flushdb", "erase every key in a Redis database (FLUSHDB)", "database"),
  ],
  gh: [e("repo delete", "delete a GitHub repository", "repo")],
  git: [e("reflog expire", "git reflog expire --expire=now --all removes the history git keeps to recover lost commits", "history", { when: (x) => x.args.some((a) => /^--expire(?:-unreachable)?=now$/.test(a.text)) && hasFlag(x.args, "--all") })],
};

/** One catastrophic table entry, as the tests see it (read-only; the engine does not use this). */
export interface CatastrophicEntrySummary {
  tool: string;
  path: readonly string[];
  first: boolean;
  /** The entry matches only under a condition (a flag such as --recursive or --force). */
  conditional: boolean;
  /** A matched command can still be demoted to an ask (a targeted teardown). */
  demotable: boolean;
  what: string;
  kind: CatastropheKind;
}

/** Every entry of the command tables, so a test can probe each one (kubectl and gh api are judged by code, not a table). */
export function catastrophicTableEntries(): CatastrophicEntrySummary[] {
  return Object.entries(TABLES).flatMap(([tool, entries]) => entries.map((x) => ({ tool, path: x.path, first: x.first === true, conditional: x.when !== undefined, demotable: x.demote !== undefined, what: x.what, kind: x.kind })));
}

/** The program aliases folded onto a table (flyctl is fly, podman is docker...), for the tests. */
export function catastrophicAliases(): Readonly<Record<string, string>> {
  return { ...ALIASES };
}

/** heroku apps:destroy takes the app from -a/--app or as its first argument. */
function herokuApp(x: Ctx): CmdWord[] {
  for (let i = 0; i < x.args.length; i++) {
    const t = (x.args[i] as CmdWord).text;
    if (t === "-a" || t === "--app") {
      const v = x.args[i + 1];
      return v === undefined ? [] : [{ text: v.text, dynamic: v.dynamic }];
    }
    if (t.startsWith("--app=")) return [{ text: t.slice(6), dynamic: (x.args[i] as CmdWord).dynamic }];
  }
  return FIRST_AFTER(x);
}

const ALIASES: Readonly<Record<string, string>> = { flyctl: "fly", podman: "docker", nerdctl: "docker", neon: "neonctl", oc: "kubectl" };

/** Whether `path` matches the positionals at `i` (dynamic positionals match anything): "exact", "maybe" (a dynamic word stood in), or null. */
function matchAt(pos: readonly Pos[], i: number, path: readonly string[]): "exact" | "maybe" | null {
  let maybe = false;
  for (let j = 0; j < path.length; j++) {
    const p = pos[i + j];
    if (p === undefined) return null;
    if (p.text === path[j]) continue;
    if (p.dynamic) {
      maybe = true;
      continue;
    }
    return null;
  }
  return maybe ? "maybe" : "exact";
}

/** The tables' tool name for a program (aliases folded), or null when it has no table. */
export function catastrophicTool(name: string): string | null {
  const tool = own(ALIASES, name) ?? name;
  return own(TABLES, tool) !== undefined || tool === "kubectl" ? tool : null;
}

/**
 * Whether running `name` with `words` (the words after the program name) is catastrophic (deny), or an
 * ordinary destructive action after all (ask: a targeted teardown, a scratch target, a verb known only at
 * run time). Null: neither.
 */
export function judgeCommand(name: string, words: readonly CmdWord[], o: CatastropheOptions = {}): Judgement | null {
  const tool = catastrophicTool(name);
  if (tool === null) return null;
  if (hasFlag(words, "--help") || (!H_IS_HOST.has(tool) && hasFlag(words, "-h"))) return null;
  if (tool === "kubectl") return kubeDelete(name === "oc" ? "oc" : "kubectl", words, o);
  if (tool === "gh") {
    const api = ghApiDelete(words);
    if (api !== null) return api;
  }
  const table = own(TABLES, tool) ?? [];
  const pos = positionals(tool, words);
  let maybe: Entry | null = null;
  for (const entry of table) {
    const starts = entry.first === true ? [0] : pos.map((_, i) => i);
    for (const i of entry.path.length === 0 ? [0] : starts) {
      const m = matchAt(pos, i, entry.path);
      if (m === null) continue;
      const x: Ctx = { args: words, pos, after: pos.slice(i + entry.path.length) };
      if (entry.when !== undefined && !entry.when(x)) continue;
      if (m === "maybe") {
        maybe ??= entry;
        continue;
      }
      const demoted = entry.demote?.(x) ?? null;
      if (demoted !== null) return ask(`${demoted}; it cannot be undone, so it needs you`);
      const names = entry.targets?.(x) ?? [];
      const pattern = entry.targets !== undefined ? scratchFor(names, o.scratch) : null;
      return pattern !== null ? scratchAsk(entry.what, names, pattern) : deny(entry.what, entry.kind === "database" && entry.targets !== undefined ? "databaseScratch" : entry.kind);
    }
  }
  if (maybe !== null) return ask(`${name} with words known only at run time (${pos.filter((p) => p.dynamic).map((p) => p.text).join(" ")}): it could ${maybe.what}`);
  return null;
}

/** Back-compat for the tests: words as plain text (none dynamic), deny reasons only. */
export function catastrophicCommand(name: string, args: readonly string[], o: CatastropheOptions = {}): string | null {
  const j = judgeCommand(name, args.map((text) => ({ text, dynamic: false })), o);
  return j?.level === "deny" ? j.reason : null;
}

// --- git push ------------------------------------------------------------------------------------------

/** Whether a branch name is protected: main, master, trunk, or a pattern from the policy. */
export function isProtectedBranch(branch: string, extra: readonly string[] = DEFAULT_PROTECTED_BRANCHES): boolean {
  const b = branch.toLowerCase();
  return CORE_PROTECTED_BRANCHES.includes(b) || extra.some((p) => globName(p.toLowerCase(), b));
}

/** The ref a refspec writes on the remote (`src:dst` gives dst, `+main` gives main), without refs/heads/. */
function destinationRef(spec: string): string {
  const s = spec.replace(/^\+/, "");
  const dst = s.includes(":") ? s.slice(s.lastIndexOf(":") + 1) : s;
  return dst.replace(/^refs\/heads\//, "");
}

/** Options of git push that take a value (so the value is not a remote or a refspec). */
const PUSH_VALUE_OPTS = new Set(["-o", "--push-option", "--repo", "--receive-pack", "--exec"]);

/**
 * `git push` (the words after "push") that rewrites or deletes a protected branch: a force (--force, -f in
 * a flag group, --force-with-lease, a +refspec) or a mirror onto one, deleting one, or forcing every branch.
 * A force push that names no branch (or names HEAD) pushes the branch checked out: `current()` reads it
 * (null when it cannot be read: then the push is asked, not denied). A dry run changes nothing.
 */
export function judgePush(words: readonly CmdWord[], current: () => string | null, o: CatastropheOptions = {}): Judgement | null {
  const specs: CmdWord[] = [];
  let remoteSeen = false;
  let force = false;
  let del = false;
  let dry = false;
  let all = false;
  let mirror = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as CmdWord;
    const a = w.text;
    if (PUSH_VALUE_OPTS.has(a)) {
      i++;
      continue;
    }
    if (a === "--dry-run") dry = true;
    else if (a === "--mirror") mirror = true;
    else if (a === "--all" || a === "--branches") all = true;
    else if (a === "--force" || /^--force-with-lease(?:=|$)/.test(a)) force = true;
    else if (a === "--delete") del = true;
    else if (/^-[a-zA-Z]+$/.test(a)) {
      if (a.includes("n")) dry = true;
      if (a.includes("f")) force = true;
      if (a.includes("d")) del = true;
    } else if (!a.startsWith("-")) {
      if (!remoteSeen) remoteSeen = true;
      else specs.push(w);
    }
  }
  if (dry) return null;
  const extra = o.protectedBranches ?? DEFAULT_PROTECTED_BRANCHES;
  if (mirror) return deny("git push --mirror overwrites every branch on the remote, the protected ones included", "git");
  if (all && force) return deny("git push --force --all overwrites every branch on the remote, the protected ones included", "git");
  const dynamicSpec = specs.find((s) => s.dynamic);
  if (dynamicSpec !== undefined && (force || del || dynamicSpec.text.startsWith("+") || dynamicSpec.text.startsWith(":"))) return ask(`git push ${force ? "--force " : del ? "--delete " : ""}to a branch known only at run time (${dynamicSpec.text}): it could be a protected branch`);
  for (const spec of specs) {
    const dst = destinationRef(spec.text);
    const named = dst === "HEAD" ? current() : dst;
    if (named === null) {
      if (force) return ask("git push --force of HEAD, and the branch checked out could not be read: it could be a protected branch");
      continue;
    }
    // A destination with a glob (refs/heads/*:refs/heads/*) writes every branch it matches, the protected ones included.
    // A destination too long to compile as a pattern is judged as matching: the analyzer must never throw on hostile text.
    const globbed = /[*?[]/.test(named) && (named.length > 256 || [...CORE_PROTECTED_BRANCHES, ...extra].some((b) => globName(named.toLowerCase(), b.toLowerCase())));
    if (!globbed && !isProtectedBranch(named, extra)) continue;
    if (del || spec.text.startsWith(":")) return deny(`git push deletes the protected branch "${named}" on the remote`, "git");
    if (force || spec.text.startsWith("+")) return deny(`git push --force rewrites the history of the protected branch "${named}" on the remote, discarding everyone else's commits`, "git");
  }
  if (specs.length === 0 && force) {
    const branch = current();
    if (branch === null) return ask("git push --force of the branch checked out, which could not be read: it could be a protected branch");
    if (isProtectedBranch(branch, extra)) return deny(`git push --force of the branch checked out, "${branch}", rewrites the history of a protected branch on the remote, discarding everyone else's commits`, "git");
  }
  return null;
}

/** Back-compat for the tests: words as plain text, the checked-out branch unknown, deny reasons only. */
export function catastrophicPush(args: readonly string[], o: CatastropheOptions = {}): string | null {
  const j = judgePush(args.map((text) => ({ text, dynamic: false })), () => null, o);
  return j?.level === "deny" ? j.reason : null;
}

/**
 * The branch checked out in the repository that contains `cwd`: `.git/HEAD`, or a worktree's `.git` file
 * pointing at its git directory. Null when it cannot be read or HEAD is detached.
 */
export function currentBranch(cwd: string, readFile: ((abs: string) => string | null) | undefined): string | null {
  if (readFile === undefined || !cwd.startsWith("/")) return null;
  const read = (p: string): string | null => {
    try {
      return readFile(p);
    } catch {
      return null;
    }
  };
  let dir = cwd.replace(/\/+$/, "") || "/";
  for (let depth = 0; depth < 64; depth++) {
    const base = dir === "/" ? "" : dir;
    let head = read(`${base}/.git/HEAD`);
    if (head === null) {
      const pointer = read(`${base}/.git`);
      const m = pointer === null ? null : /^gitdir:\s*(.+?)\s*$/m.exec(pointer);
      if (m !== null) {
        const gitdir = (m[1] as string).startsWith("/") ? (m[1] as string) : `${base}/${m[1] as string}`;
        head = read(`${gitdir.replace(/\/+$/, "")}/HEAD`);
        if (head === null) return null;
      }
    }
    if (head !== null) {
      const ref = /^ref:\s*refs\/heads\/(.+?)\s*$/m.exec(head);
      return ref === null ? null : (ref[1] as string);
    }
    if (dir === "/") return null;
    dir = dir.slice(0, dir.lastIndexOf("/")) || "/";
  }
  return null;
}

// --- SQL -----------------------------------------------------------------------------------------------

/**
 * SQL that removes a whole database: DROP DATABASE or DROP SCHEMA, MongoDB's dropDatabase(), Redis's
 * FLUSHALL/FLUSHDB, wherever the database is (the firewall cannot tell a scratch database from a real one
 * by itself: PGHOST or DATABASE_URL may point anywhere; the scratch allowlist can). TRUNCATE empties tables
 * and counts when the database is named on a remote host; locally, and through an MCP tool, it stays an
 * ordinary destructive action.
 */
export function judgeSql(sql: string, remote: boolean, o: CatastropheOptions = {}): Judgement | null {
  const { text } = stripSql(sql);
  for (const stmt of sqlStatements(text)) {
    const m = /^\s*DROP\s+(DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?([\s\S]*)$/i.exec(stmt);
    if (m !== null) {
      const what = `drop a whole ${(m[1] as string).toUpperCase() === "SCHEMA" ? "database schema" : "database"} (DROP ${(m[1] as string).toUpperCase()})`;
      const names = (m[2] as string).replace(/\s+(?:CASCADE|RESTRICT|WITH\s*\(.*\))\s*$/i, "").split(",").map((s) => s.trim()).filter((s) => s !== "");
      // A quoted name is replaced by a placeholder when literals are removed, so it can never match a pattern.
      const words = names.map((n) => ({ text: n, dynamic: !/^[A-Za-z0-9_.-]+$/.test(n) || n === "ident" }));
      const pattern = scratchFor(words, o.scratch);
      return pattern !== null ? scratchAsk(what, words, pattern) : deny(what, "databaseScratch");
    }
    if (remote && /^\s*TRUNCATE\b/i.test(stmt)) return deny("empty tables in a remote database (TRUNCATE)", "database");
  }
  if (/\bdropDatabase\s*\(/.test(text)) return deny("drop a whole MongoDB database (dropDatabase)", "database");
  if (/\bFLUSH(?:ALL|DB)\b/i.test(text)) return deny("erase every key in a Redis database (FLUSHALL/FLUSHDB)", "database");
  return null;
}

/** Back-compat for the tests: deny reasons only. */
export function catastrophicSql(sql: string, remote: boolean, o: CatastropheOptions = {}): string | null {
  const j = judgeSql(sql, remote, o);
  return j?.level === "deny" ? j.reason : null;
}

// --- MCP tools by name ---------------------------------------------------------------------------------

const MCP_CATASTROPHIC: readonly { re: RegExp; what: string; kind: CatastropheKind }[] = [
  { re: /^delete_?(?:project|projects)$/, what: "delete a whole project", kind: "cluster" },
  { re: /^delete_?(?:repository|repo)$/, what: "delete a repository", kind: "repo" },
  { re: /^delete_?(?:database|db)$/, what: "delete a database", kind: "database" },
  { re: /^delete_?namespace$/, what: "delete a namespace with everything in it", kind: "cluster" },
  { re: /^drop_.+$/, what: "drop a database object with its data", kind: "database" },
];

/** An MCP tool whose name says it deletes a whole project, repository, database or namespace (drop_*). */
export function judgeMcpTool(tool: string): string | null {
  const n = tool.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/-/g, "_").toLowerCase();
  const hit = MCP_CATASTROPHIC.find((x) => x.re.test(n));
  return hit === undefined ? null : catastropheReason(hit.what, hit.kind);
}

/** The reason for deleting a whole workspace root (or a directory that contains one). */
export function workspaceDeletion(target: string): string {
  return catastropheReason(`delete the whole workspace ${target}`, "workspace");
}

/** The reason for deleting a repository's .git directory: its whole history. */
export function gitDirDeletion(target: string): string {
  return catastropheReason(`delete ${target}, the repository's whole history and every branch not pushed`, "git");
}
