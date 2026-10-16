# Releasing

The maintainers' release checklist for `@launchsafe/agent-firewall` (npm). The
Python SDK (`python/`, PyPI `launchsafe-firewall`) and the browser extension
(`browser/`) are released separately and are not covered here.

Nothing in this file needs a secret. The npm workflow publishes with npm
trusted publishing (OIDC): there is no `NPM_TOKEN`, and none should be created.
The one exception to publishing from the workflow is the very first version,
which a maintainer signed in to npm with 2FA publishes once by hand
([The first version](#the-first-version)).

## One-time setup

### GitHub: the `npm-release` environment

`.github/workflows/release.yml` publishes from a job in the `npm-release`
environment, and npm accepts publishes only from that environment.

1. Repository **Settings > Environments > New environment**, named
   `npm-release`.
2. Where it is available on the repository's current plan, add **required
   reviewers** (the maintainers) and a **deployment tag rule** `v*.*.*`. On a
   private repository these protection rules may need a paid plan; do not
   upgrade or enable paid features for them. They are available on a public
   repository, so add them when the repository becomes public (below). The
   environment name alone still ties npm's trust to this workflow, and the
   workflow's own checks still apply.
3. Add no secrets to the environment.

### GitHub: a public repository

The workflow publishes with `npm publish --provenance`, and `package.json` sets
`"provenance": true` under `publishConfig`, so every publish asks npm for a
provenance statement. npm accepts a provenance statement only from a **public**
source repository: a publish with provenance from a private repository is
rejected, and nothing is published. So `shivanagendrakore/agent-firewall` must be
public before the Release workflow publishes (from the second version on; the
first is published by hand, see [The first version](#the-first-version)).
Making it public is the maintainers' decision, like removing `private` from
`package.json`. A dry run of the workflow publishes nothing, so it also works
while the repository is private.

### npm: who can publish

The first version needs a maintainer whose npm account has two-factor
authentication and may publish under the `@launchsafe` scope (a member of the
`launchsafe` npm organization with write access to its packages).

Before the first publish, on npmjs.com (verify each point there; npm's screens
change):

1. The `launchsafe` organization exists and owns the `@launchsafe` scope
   (npm: **Add Organization**; a scope is created with its organization). If
   the scope or the name is taken by someone else, stop: the package name has
   to change.
2. The publishing account is a member of that organization with permission to
   publish (verify on npmjs.com which role grants it), and has two-factor
   authentication enabled for authorization and publishing.
3. `npm whoami` after `npm login` prints that account, and
   `npm access list packages @launchsafe` (or the organization's Packages page)
   shows what the scope holds, which for the first version is nothing.

### npm trusted publishing

npm can add a trusted publisher only to a package that already exists, so do
this right after the first version is on npm
([The first version](#the-first-version), step 4).

1. On npmjs.com, open the package `@launchsafe/agent-firewall` > **Settings >
   Trusted publishing**, choose **GitHub Actions**, and enter:
   - Organization or user: `shivanagendrakore`
   - Repository: `agent-firewall`
   - Workflow filename: `release.yml`
   - Environment: `npm-release`
2. Under **Publishing access**, choose "Require two-factor authentication and
   disallow tokens", so only the trusted workflow (or a maintainer with 2FA)
   can publish.
3. If an `NPM_TOKEN` repository secret exists from an earlier setup, delete it.
4. Verify on npmjs.com that the four fields match the workflow exactly (they
   are case-sensitive, and npm does not check them until a publish runs): the
   workflow file is `.github/workflows/release.yml`, written as
   `release.yml`; its `publish` job declares `environment: npm-release` and
   `permissions: id-token: write`; and the npm CLI it uses is 11.5.1 or newer
   (the workflow installs npm 11.6.2).
5. If a classic or granular npm token was ever created for this package (for
   the first version or a test), revoke it on npmjs.com under **Access Tokens**.
   The first-version steps below use a web login and need no token.

If trusted publishing is not set up, the publish step fails with a message
pointing here (npm answers `ENEEDAUTH`, `E401`, `E403` or `E404`), and nothing
is published. That is expected for the first version. A publish from a private
repository fails too, with an error that names the repository's visibility
([a public repository](#github-a-public-repository)).

## Before the release

1. Work from an up-to-date `main` with CI green.
   The public repository must exist at
   <https://github.com/shivanagendrakore/agent-firewall> before the Release
   workflow can publish with provenance
   ([a public repository](#github-a-public-repository)).
2. **Typosquat name lists (needs the network).** The typosquat check compares
   package names with the lists in `src/data/popular-npm.ts`,
   `popular-pypi.ts`, `popular-crates.ts` and `popular-rubygems.ts`. Until the
   first release they are hand-picked seed lists whose headers say "Replace at
   release". Regenerate them before every release, from the root of an
   up-to-date clone of `main` (Node 22.13 or newer, not 23 or 25, to build or test; 22 or newer to run):

   ```sh
   node scripts/gen-popular.mjs
   ```

   - **Where it runs.** The script downloads public download rankings (the npm
     registry's search API, the crates.io API, and a PyPI ranking published on
     GitHub Pages), so run it on a maintainer's machine, or in a CI job that has
     network access (no workflow in this repository runs it today; whoever
     runs it reviews and commits the diff). It cannot run offline, in a
     container or sandbox without network such as an offline test box: the
     first failed download stops it with an error, and a file it already
     rewrote for an earlier ecosystem stays rewritten, so check
     `git status src/data` before you commit anything.
   - **Before you run it**, check that the sources named in the script's header
     are still the ones to use (the header marks that choice as open). By
     default it rewrites all three files it covers (`--eco npm|pypi|crates`
     picks one): the top 5,000 names become targets, and the names ranked
     after them, up to 20,000, join the reviewed known names already in the
     file (`--targets`, `--known`). The crates.io part waits a second between
     requests, so it takes a few minutes.
   - **RubyGems is not covered**: there is no public top-downloads list, so
     `popular-rubygems.ts` stays hand-kept. Review it by hand, and correct its
     header, which still says to replace it with the script.
   - **Review the diff.** Only names, the source and the date should change,
     and every name should be a plain package name (letters, digits, `.`, `_`,
     `-`, and `@` and `/` in npm scopes). The files are TypeScript source and
     the names are written into it unchecked, so a backtick or a dollar sign
     from a source would become code: drop such a name. Then run the local
     checks in step 5: the typosquat tests in `npm test` check that no listed
     name is flagged, and `npm run conformance:check`, `npm run friction` and
     `npm run bench` also read these lists. If one of them fails, a name that a
     test or the friction corpus installs now looks like a typo of a newly
     listed name: find out why before you change a list or a test. Commit the
     regenerated files. A regenerated file no longer says "Replace at release".
     The firewall and its tests never fetch these lists.
3. **Version and changelog.** Set the version without tagging:
   `npm version <x.y.z> --no-git-tag-version` (updates `package.json` and
   `package-lock.json`). `npm version` does not touch `src/version.ts`: set
   `VERSION` there to the same version (the CLI's `--version` prints it,
   `install` records it and `docs/coverage.json` carries it), then run
   `npm run gen:docs`. Move the `CHANGELOG.md` entries under the new version
   with the release date. For 0.3.0 all of these already say 0.3.0
   (`npm version` refuses an unchanged version, so skip it); only the date is
   left, in step 4.
4. **First release only: the pre-release wording.** `README.md` and
   `docs/usage.md` ship in the package and say it is not published yet. They
   stay true until the release, so change them only now, in the same pull
   request as the version and changelog (step 3): the commit you tag is the one
   the package is built from, so it must already have the release wording.
   Line numbers are as of this writing; search for the quoted text.
   - `README.md` lines 13-15, the status note. Remove it:

     ```text
     > **Status: pre-release.** Local only, not yet published to npm. The npm badge
     > and the npm command work after release. Until then, install from a checkout
     > as in the Quick start.
     ```

   - `README.md` lines 59-61, the Quick start's first sentence, and the
     commands at lines 63-70. Make `npm install -g @launchsafe/agent-firewall`
     the install line; keep the warning against `npx` and shell aliases and the
     `install` and `doctor` lines:

     ```text
     Until the package is published, build it from a checkout and install the
     packed tarball into its own prefix (Node 22.13 or newer, not 23 or 25, to build or test; 22 or newer to run). Do not run it with
     `npx` or a shell alias: the hooks need a stable path to the CLI.
     ```

   - `README.md` lines 72-73. Remove it, or turn it into a pointer to building
     from a checkout:

     ```text
     After release, `npm install -g @launchsafe/agent-firewall` replaces the first
     four lines.
     ```

   - `README.md` lines 161-162, under "What is in this repository". Say that the
     npm package is published and the Python SDK and the browser extension are
     not yet (unless they are by then):

     ```text
     Each part has its own package file, tests and release. None of them is
     published yet.
     ```

   - `docs/usage.md` lines 15-17, in "Try the demo". Give the installed
     command, `launchsafe-firewall demo`:

     ```text
     From a
     checkout today:
     `npm ci && npm run build && node dist/cli.js demo`.
     ```

   - `docs/usage.md` lines 23-26, in "Step by step", with the commands of
     "1. Install" at lines 30-36 and the paragraph after them at lines 38-40
     (the packed install and its stable path). Install from npm instead, and
     keep the Node, platform and Windows wording:

     ```text
     The package is not published yet, so
     build it from a checkout (Node 22.13 or newer, not 23 or 25, to build or test; 22 or newer to run, on macOS or Linux; Windows is not
     supported and the firewall refuses to run there, see
     [limitations](limitations.md)):
     ```

   - `docs/usage.md` lines 215-217, under "Install":

     ```text
     Until the package is published, install from a checkout as in
     [step 1](#1-install). After release, `npm install -g @launchsafe/agent-firewall`
     replaces the clone, build and pack lines.
     ```

   - `CHANGELOG.md` line 7, `## [0.3.0] - unreleased`: replace `unreleased`
     with the release date (`YYYY-MM-DD`). The text under it
     (`First public release.`) says nothing about npm, so nothing else in the
     changelog needs to change.

   Leave the "not released" notes of the browser extension and the Python SDK
   (`README.md` lines 34 and 178, `docs/browser-link.md`, `python/README.md`)
   alone: they are released separately. Afterwards, search `README.md` and
   `docs/` for "not yet published", "not published yet", "Until the package is
   published" and "After release": none should be left. `npm run check:docs`
   does not check this wording.
5. **Local checks**, from the root:

   ```sh
   npm ci
   npm run typecheck && npm run lint && npm run build
   npm run check:docs
   node scripts/sync-agent-safety.mjs --check
   npm run conformance:check
   npm test
   npm run friction && npm run mail-friction
   npm run bench                  # p95 < 50 ms, p99 < 150 ms
   gitleaks dir .                 # no leaks (CONTRIBUTING.md, secret scanning)
   grep -rEl "sk_live_[A-Za-z0-9]{10}|AKIA[0-9A-Z]{16}|xoxb-[0-9]{6}|npm_[A-Za-z0-9]{30}" dist   # no output: no complete fake secret ships in dist (src/catalogue.ts builds its fakes from parts)
   npm audit --omit=dev --audit-level=high
   npm pack --dry-run             # read the file list
   ```

   The build starts from an empty `dist/` (`scripts/clean-dist.mjs`), so a
   module whose source was deleted cannot ship; `prepack` runs the same build.
   The v0.2 upgrade tests (`test/lifecycle/upgrade.test.ts`) need the
   `v0.2/final` ref; run them where it exists (or set `LSFW_V02_REF`). The
   ripgrep test in `test/canary.test.ts` needs `rg`, and the sandbox tests in
   `test/run-sandbox.test.ts` need `sandbox-exec` (macOS) or a working
   bubblewrap (Linux); without them those tests skip. The release workflow
   installs and checks them the way CI does, so they run there.
6. **macOS sandbox evidence (a Mac, by hand).** `release.yml` runs on Linux
   only, and macOS runner minutes cost ten times Linux's, so the macOS suites
   (the Seatbelt profile behind `run`, and the macOS-only regressions) run on a
   maintainer's Mac, on the commit to be released, before the tag. From the
   root of a clean checkout of that commit, after `npm ci`:

   ```sh
   git rev-parse HEAD
   npx vitest run test/run-sandbox.test.ts test/gemini-seatbelt.test.ts \
     test/review-v03/regressions.test.ts test/self-protection-aliases.test.ts
   ```

   (`npm test` is `vitest run`, so this is the project's normal test script
   narrowed to these files.) `sandbox-exec` must be present, or those suites
   skip: a skip is not a pass, so read the output and require zero skipped in
   these files. Record the commit sha and the result (pass counts, date,
   macOS version) in the release notes and in your release record. Then give
   the Release workflow the sha: set the repository variable
   `MACOS_VERIFIED_SHA` (Settings > Secrets and variables > Actions >
   Variables), or enter it as the `macos_verified_sha` input of a manual run.
   A real release stops unless that sha equals the release commit's sha, so
   any commit after the Mac run needs a new run. A dry run only warns.
7. **The v0.2 upgrade tests (private development repository).** The public
   repository starts from one fresh commit and has no `v0.2/final` ref, so
   `test/lifecycle/upgrade.test.ts` skips there (the release workflow says so
   in a notice). Before building the single release commit, run them in the
   private development repository, which has the ref (set `LSFW_V02_REF` to
   `v0.2/final` or `origin/v0.2/final` if the tests do not find it):

   ```sh
   LSFW_V02_REF=v0.2/final npx vitest run test/lifecycle/upgrade.test.ts
   ```

   Record the result and the commit it ran on in the release record. Run it
   on the same tree that becomes the release commit.
8. **Package contents.** `npm pack --dry-run` lists what would ship: `dist/`
   (with `dist/hook/bundle.js`), `docs/`, `README.md`, `LICENSE` and `NOTICE`,
   and nothing from `test/`, `conformance/`, `browser/` or `python/`. The
   release workflow checks the list with `scripts/check-pack.mjs`, which also
   requires every file under `docs/` and the Onest font's licence
   (`docs/licenses/Onest-OFL.txt`: the dashboard embeds the font, and `NOTICE`
   points there), and fails if anything is wrong. To run the same check
   locally after a build:
   `npm pack --dry-run --ignore-scripts --json > /tmp/pack.json && node scripts/check-pack.mjs /tmp/pack.json`.
9. **Dry run in CI.** Actions > Release > Run workflow on `main`, leaving
   "Run every check but do not publish" ticked. It runs every check and the
   package-contents assertion and publishes nothing.

## Decide to publish

`package.json` has `"private": true` until the maintainers decide to publish.
Removing it is that decision: do it in its own reviewed pull request to `main`.
A real release refuses to run while the flag is there.

## Tag and publish

1. After the version, changelog, wording and `private` changes are merged, tag
   the merge commit on `main` and push the tag:

   ```sh
   git switch main && git pull --ff-only
   git tag -s v<x.y.z> -m "v<x.y.z>"
   git push origin v<x.y.z>
   ```

2. The tag starts the Release workflow. Its `verify` job checks that the tag
   matches the version, that `private` is gone and that the tagged commit is an
   ancestor of `origin/main`, then runs every check, including every command
   CI's test job runs on Linux (`test/release.test.ts` keeps the two workflows
   in step). `release.yml` runs on Linux only, so the macOS evidence for `run`
   (the Seatbelt profile) comes from a manual run on a Mac before release: make
   it a pre-release checklist item. The `publish` job then
   waits in the `npm-release` environment (for approval, where reviewers are
   set), checks the same three things again, and runs
   `npm publish --provenance --access public` with an OIDC token.
3. A tag on a commit that is not on `main` is refused, and nothing is
   published.

For the first version (v0.3.0) the `publish` job cannot succeed: follow
[The first version](#the-first-version).

## The first version

npm can add a trusted publisher only to a package that already exists, so the
first version is published once by hand, and the workflow publishes every
version after it. Publishing it from CI instead would need an npm token, which
this process does not use.

1. Do everything above up to and including pushing the tag `v0.3.0`.
2. **The workflow's `publish` job fails for this version, as expected.** The tag
   push starts the Release workflow. Let its `verify` job finish and pass: it is
   the check of the tagged commit that the hand publish relies on. Its
   `publish` job cannot succeed, because no trusted publisher exists yet (and,
   while the repository is private, npm would also refuse the provenance).
   Where required reviewers are set, reject the waiting deployment; otherwise
   let the job fail. Either way nothing is published. Do not re-run that job
   later: once 0.3.0 is on npm, npm refuses to publish the same version again.
3. **Publish by hand.** A maintainer ([who can publish](#npm-who-can-publish))
   publishes from a fresh clone of the tag, not from a working copy:

   ```sh
   git clone --branch v0.3.0 https://github.com/shivanagendrakore/agent-firewall.git lsfw-v0.3.0
   cd lsfw-v0.3.0 && git tag -v v0.3.0              # the tag's signature
   npm ci
   npm login --auth-type=web                        # the maintainer's account, with 2FA
   npm publish --provenance=false --access public   # this command only; see below
   ```

   `--provenance=false` is needed. `publishConfig` in `package.json` turns
   provenance on, and npm can make a provenance statement only inside a
   supported CI system, so a plain `npm publish` from a maintainer's machine
   stops with an error and publishes nothing. The flag turns provenance off for
   this one command; do not remove `provenance` from `package.json`. A flag
   given on the command line wins over `publishConfig` in the npm that comes
   with a current Node 22 (npm 10.9) and in npm 11; check `npm --version`
   first. The publish builds the package through `prepack`. This first version
   has no provenance statement.
4. **Set up [npm trusted publishing](#npm-trusted-publishing)** now that the
   package exists, including "Require two-factor authentication and disallow
   tokens".
5. **Make the repository public** before the next release, if it is not yet
   ([a public repository](#github-a-public-repository)), and add the
   environment's protection rules then.
6. Go on with [After the release](#after-the-release). There is no provenance
   statement to check for this version.

From the next version on, the tag push publishes through the workflow, with
provenance, and nothing is published by hand.

## After the release

1. Check the package page on npmjs.com: the version, the file list, and the
   provenance statement linking to the workflow run (not for the first
   version).
2. Install it in a scratch directory with a throwaway `HOME`, and run the
   installed command by its path:

   ```sh
   (
     scratch="$(mktemp -d)" && export HOME="$scratch/home" && mkdir "$HOME"
     npm install --prefix "$scratch" @launchsafe/agent-firewall@<x.y.z>
     "$scratch/node_modules/.bin/launchsafe-firewall" --version   # prints <x.y.z>
   )
   ```

   Do not check it with a bare `npx launchsafe-firewall`: when npx does not
   find that command in the current directory's packages (the scratch install
   failed, or you are in another directory), it looks for the unscoped name
   `launchsafe-firewall` on the registry instead, which is not this package
   and may be anyone's, and offers to install and run it. To use npx, name the
   scoped package:
   `npx --package=@launchsafe/agent-firewall@<x.y.z> launchsafe-firewall --version`.
3. Create the GitHub release by hand from the tag, with the changelog section
   as its notes (the workflow has no `contents: write`, so it does not).
4. Open the next `## [Unreleased]` section in `CHANGELOG.md`.

If a release is broken, publish a fixed patch version. Use `npm deprecate` on
the broken version rather than `npm unpublish`.
