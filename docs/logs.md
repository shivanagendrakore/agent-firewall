# The decision log: export, verify anywhere, anchor off the machine

Every decision the firewall makes is written to a JSON-lines log under
`~/.launchsafe-firewall/log/`, each entry chained to the one before it by
SHA-256 and signed with a local Ed25519 key (`docs/design.md`, "Runtime:
durability and concurrency"). An I/O failure such as a full disk is the one
exception, and the log keeps a bounded history; both are under
[Limits](#limits). `launchsafe-firewall log verify` checks that log in place.
This page covers the three commands that take the log off the machine:

| Command | What it does | Who may run it |
|---|---|---|
| `log export --out FILE` | writes the log, or a range of it, as one signed, self-contained bundle | a person at a terminal (refused for agents) |
| `log verify <bundle>` | checks a bundle anywhere, offline, with no firewall install | anyone (read-only) |
| `log anchor --file/--git-notes/--exec` | writes the log's current head to a place you choose | a person at the keyboard only |

## Why anchor at all

The signing key lives in the firewall's own directory (`docs/limitations.md`).
`log verify` proves the log is intact against everyone who cannot write that
directory. Someone who can write it holds the key, and can rewrite the whole
history with a valid chain and valid signatures, or cut the log back to an
older signed head. Nothing inside the directory can prove otherwise. An anchor
can: it is a signed record of "entry N had hash H", kept somewhere the
firewall's directory cannot reach. A later bundle whose entry N has a different
hash, or which ends before N, fails against it.

## log export

```sh
launchsafe-firewall log export --out ~/Desktop/fw-log-2026-10.jsonl
launchsafe-firewall log export --out week.jsonl --from 2026-10-06 --to 2026-10-12T23:59:59Z
launchsafe-firewall log export --out part.jsonl --from 1200 --to 1500
launchsafe-firewall log export --out - | gzip > log.jsonl.gz
```

Export is person-run. The real gate is the hook: an agent's tool call that runs
it (directly, through `sh -c`, `env` or `npx`) is `FW-TAMPER`. As a second line,
the command itself wants a terminal on standard input (standard output may be a
pipe) and refuses a descendant of a Claude Code session; an agent able to fake a
terminal outside the hooks' view could pass that check, which is why the hook
is the gate.

- `--from` and `--to` take a sequence number (digits alone are always a
  sequence number, so `2026` is entry 2026, not the year) or an ISO 8601 date
  (`2026-10-01`, midnight UTC) or date and time with a zone
  (`2026-10-01T12:00:00Z`, `2026-10-01T14:00:00+02:00`). A time without a zone,
  a year or year and month alone, and other forms are refused. A time range is the contiguous run of entries from the first at or after
  `--from` to the last at or before `--to`, by sequence number, so a clock that
  went backwards cannot leave a hole in the chain.
- The export refuses a log that does not pass `log verify` (copy the files
  under `~/.launchsafe-firewall/log/` for forensics instead), an empty range,
  an `--out` file that already exists or is a symbolic link, and an `--out`
  inside the firewall's directory. The file is created with mode 0600 and
  reported written only after it reads back as the bundle that verified.
- It prints the key's fingerprint (`sha256:` and 64 hex digits). Keep that
  somewhere other than this machine: it is what proves later that a bundle came
  from this install.
- The bundle holds exactly what the log holds: each entry is the same JSON
  object the log wrote. Nothing is redacted and nothing is added: summaries that were bounded when they were
  logged (a long tool name keeps its first 1,024 characters and the hash of the
  whole) stay bounded. Treat a bundle as you treat the log: it names files,
  hosts and commands the agent touched.

### The bundle format (version 1)

JSON lines. Line 1 is the header; every further line is one log entry as the
firewall wrote it (`seq`, `ts`, `prev`, `event`, `hash`, `sig`, `heads`).

```json
{"format":"launchsafe-firewall-log-bundle","version":1,
 "manifest":{"createdAt":"...","createdBy":"launchsafe-firewall 0.3.0","signer":"sha256:...",
   "requested":{"from":null,"to":null},"fromStart":true,"toEnd":true,
   "entries":412,"firstSeq":1,"lastSeq":412,"firstHash":"...","lastHash":"...","startPrev":"000...0",
   "eventTypes":{"decision":398,"session_start":14},
   "logHead":{"seq":412,"hash":"...","sig":"..."},"prunedAnchor":null},
 "keys":[{"id":"sha256:...","alg":"ed25519","spki":"<base64 DER>","fromSeq":1,"toSeq":412}],
 "sig":"<Ed25519 over the manifest and keys>"}
```

- `logHead` is the log's signed `head.json` when the bundle reaches the end of
  the log; `prunedAnchor` is the signed anchor of pruned log files when the
  bundle starts where the remaining files start.
- `keys` lists every key that signed an entry, with the sequence range it was
  valid for. A key after the first carries an `endorsement`: the key before it
  signs `launchsafe-firewall-log-key:v1:<id>:<fromSeq>`. The firewall does not
  rotate its log key today, so its exports list one key; the format and the
  verifier already handle a hand-over.
- `sig` is by the newest key over `launchsafe-firewall-log-bundle:v1\n`
  followed by the canonical JSON of `{manifest, keys}`. Each kind of signature
  covers its own label (entries, heads, pruned anchors, bundle headers, key
  hand-overs, anchor records), so no signature of one kind passes as another.

## log verify &lt;bundle&gt;

```sh
launchsafe-firewall log verify fw-log.jsonl --key sha256:3f1c...
launchsafe-firewall log verify fw-log.jsonl --key log-ed25519.pub.pem --anchor anchors.jsonl
launchsafe-firewall log verify fw-log.jsonl --no-pin --json
```

There are three results:

| Result | Exit | Meaning |
|---|---|---|
| `OK` | 0 | intact, and tied to a key you trust: a `--key` matched, or an anchor record matched (or you passed `--no-pin`) |
| `PROBLEMS` | 1 | something in the bundle is wrong; every problem is listed |
| `UNAUTHENTICATED` | 2 | intact, but neither pinned nor anchored. Anyone can make a consistent bundle with a key of their own, so this is not a pass |

A usage error exits 64. With `--json`, `ok` is true only for `OK`; `status`
(`ok`, `invalid`, `unauthenticated`), `intact` and `authenticated` say which.
`--no-pin` accepts an intact bundle as it is (the report still says it is not
authenticated): use it only when you check the signer some other way.

The verifier is one file with no dependencies beyond Node's own modules,
`dist/logbundle/verify.js` in the package (source `src/logbundle/verify.ts`).
It needs no firewall home, no key and no network, so an auditor can copy that
file and run it on its own:

```sh
node verify.js fw-log.jsonl --key sha256:3f1c... --anchor anchors.jsonl
```

It exits as `log verify` does (0, 1, 2, or 64). It checks:

- **Strict lines:** every line must be exactly what `JSON.stringify` writes for
  the value it parses to, as the firewall writes them, and carry only the
  fields its kind has (an entry: `seq`, `ts`, `prev`, `event`, `hash`, `sig`,
  `heads`; the header: `format`, `version`, `manifest`, `keys`, `sig`; and so
  on down to the keys and heads). A duplicate key, `-0`, `1.0`, a number past
  2^53, extra spacing or an unusual escape is refused, so no two JSON parsers
  can read a bundle differently.
- **Chain continuity:** sequence numbers run without a gap from `firstSeq`,
  each entry's `prev` is the hash of the one before (the first's is the
  manifest's `startPrev`), and each hash is the SHA-256 of its content.
- **Signatures:** each entry is signed by the key valid for its sequence
  number; signatures are read only from canonical base64. Once an entry carries
  `heads: "signed"`, a later one without it is a downgrade.
- **Keys over time:** each key's fingerprint matches its bytes, the ranges are
  contiguous and cover exactly the entries, and each later key is endorsed by
  the one before it.
- **The manifest:** its signature, and its counts (entries, event types) and
  first and last hash against the entries actually present.
- **The ends:** a bundle that says it starts at the log's start begins at
  sequence 1 or right after the signed anchor of pruned files; one that says it
  reaches the log's end matches the log's signed head (a head behind the last
  entry, as a power cut leaves it, is accepted when it names an entry of the
  bundle).
- **Whose key (pin semantics):** every `--key` you give must be one of the
  bundle's keys; one that is not is a problem (`PROBLEMS`), even when another
  `--key` matches. The bundle counts as pinned when at least one `--key`
  matches. A `--key` is a fingerprint (`sha256:` and 64 hex digits, as `log export`
  printed it; colons and upper case are accepted) or a file holding a PEM public
  key, such as `~/.launchsafe-firewall/keys/log-ed25519.pub.pem` copied earlier.
  Of a file, only a `-----BEGIN PUBLIC KEY-----` block is used (64 KiB at
  most), and nothing of the file is ever printed: a file that holds no such
  block is reported only as "not a fingerprint or a PEM public key". A pin
  checks the key, not who held it: entries before the pinned key's range are
  bound to it only by the hash chain, and keys after it only by endorsements
  each previous key signed. So pinning an older key also trusts every later
  key it (or its successors) endorsed: if an older key leaked, its holder can
  endorse a key of their own and sign on from there. Pin the newest key you
  recorded, and anchor (`--anchor`) to tie the history itself to a place the
  firewall's directory cannot reach. Without a pin or a matching anchor the
  result is `UNAUTHENTICATED`: a self-consistent bundle from another install,
  or one re-signed after the key was replaced, is caught only by a pin or an
  anchor.
- **Anchors:** each `--anchor` file holds anchor records (JSON lines, parsed as
  strictly as bundle lines; a line that is not one is counted, never shown).
  Each must be signed by a key of the bundle; for each record whose position the bundle
  covers, the entry there must have the anchored hash; a record past the end of
  a bundle that reaches the log's end means entries were removed after it was
  anchored. Records outside a range export are listed as not checked, but at
  least one must fall inside.

What fails: a truncated bundle, reordered, edited, duplicated or removed
entries, a line added anywhere, an edited manifest, a swapped key, a key used
outside its range or without a hand-over, a bundle from another install
(against your `--key` or anchor), and a history rewritten with the key after it
was anchored (`test/log-bundle.test.ts`, `test/log-anchor.test.ts`).

## log anchor

```sh
launchsafe-firewall log anchor --file /Volumes/Backup/fw-anchors.jsonl
launchsafe-firewall log anchor --git-notes ~/src/ops-records
launchsafe-firewall log anchor --exec -- aws s3 cp - s3://my-audit-bucket/fw/anchor-2026-10-13.json
```

It verifies the log first (an anchor must record a good history), then writes
one record for the log's last entry:

```json
{"format":"launchsafe-firewall-log-anchor","version":1,"seq":412,"hash":"...","key":"sha256:...","at":"2026-10-13T09:00:00.000Z","sig":"..."}
```

and logs a `log_anchor` entry (the sequence and hash, and which kind of place,
never the path or command). Places:

- `--file PATH`: appends the record (fsynced) to the file, so one file collects
  every anchor, and reports success only once the record reads back. The
  directory must exist; the file is never opened through a symbolic link, and
  a path inside the firewall's directory is refused. Choose a file the
  firewall's directory cannot reach: a mounted drive you unplug, a synced
  folder, a share.
- `--git-notes REPO`: adds the record to the git note `refs/notes/launchsafe-firewall-log`
  on a fixed object in that repository (the blob of the text
  `launchsafe-firewall log anchors` and a newline), with your git identity.
  Git runs without `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, the object
  directory variables and every `GIT_CONFIG*` variable, so the note lands in
  the repository you named; a repository inside the firewall's directory is
  refused.
  Push it yourself: `git -C REPO push origin refs/notes/launchsafe-firewall-log`.
  To verify against it, write the note to a file first:

  ```sh
  git -C REPO notes --ref launchsafe-firewall-log show \
    "$(printf 'launchsafe-firewall log anchors\n' | git -C REPO hash-object --stdin)" > anchors.jsonl
  launchsafe-firewall log verify fw-log.jsonl --anchor anchors.jsonl
  ```
- `--exec -- <command> [args...]`: the command hook. The command runs without a
  shell (its arguments reach it literally), with the record and a newline on
  its standard input; it may print up to 1 MiB and run for two minutes. A
  non-zero exit, a timeout or more output is reported and nothing is logged. Use it for any store you have a command
  for, such as an S3 bucket with Object Lock (`aws s3 cp - s3://...`), so even
  someone who holds the firewall's key cannot change what was anchored.

Anchoring is person-run only. The command needs a person at the keyboard (an
interactive terminal, not a descendant of a Claude Code session), an agent's
tool call running it is `FW-TAMPER`, and nothing in the firewall anchors on its
own. Run it on a schedule you choose (daily, before handing a bundle to
someone); an anchor covers history up to its entry, so entries after the latest
anchor have only the log's own guarantees.

## Limits

- An anchor proves "entry N had hash H at least since the anchor was written".
  Entries after the latest anchor can still be rewritten by someone with the
  key; anchor more often to narrow that window.
- Pruned log files are gone: the log rotates once the file it writes reaches
  5 MiB and keeps the 20 newest rotated files beside it (`MAX_ARCHIVES`), so an
  older entry survives only in an export or an anchor. A bundle starts at the
  signed anchor of pruned files, and an anchor record older than that cannot be
  checked against it. Export before the files are pruned if you need them.
  Each prune is recorded by the next entry as `log_pruned` (the file, its last
  sequence number and hash, and `unexported: true` when no `log export` or
  `log anchor` had covered it), and `doctor` warns about unexported prunes.
  `log export` notes the last sequence it exported in `log/exported.json`
  (beside the log, not in it, so the bundle still ends at the log's end).
  `log rotate`, which can prune, needs the approval passphrase when one is set.
- Gaps: when an entry cannot be written (a full disk), the log gives up a 1 MiB
  reserve file and retries once (`log_disk_full`); events that still cannot be
  written are counted and the next entry is a `log_gap` with the count
  (docs/limitations.md). `log verify` checks the chain, so a gap is visible
  only through these entries and `doctor`. This is the one case in which a
  decision has no entry: on such an I/O failure (a full disk, a write error, a
  lock that times out) the hook reports the error on its standard error and
  decides without one, except that an action that sends data, destroys data or
  changes the firewall or the agent's configuration is denied
  (`FW-LOG-UNRECORDED`) rather than run unrecorded; reads and workspace work go
  on.
- `log verify` in place reads each line as strictly as a bundle line (exactly
  what `JSON.stringify` writes): a line rewritten with a duplicate key or other
  spacing is reported even when its values, and so its hash, are unchanged.
- The free text a decision entry keeps about the action (`what`, and a spawned
  agent's `spawned_prompt.preview`) is stored with known credential formats
  redacted and URL query strings replaced by `?…`, whatever wrote the event.
- `log export` holds the whole remaining log in memory several times over:
  the files' text (up to about 105 MiB: 20 archives of 5 MiB each and the current
  file, which rotates at 5 MiB plus its last entry of at most 256 KiB), the
  parsed entries, and the bundle, which is about the size of the text again.
  Plan for a few hundred megabytes for a full log, or export a range.
