# Contributing

This repository holds three parts. Each has its own package file, lockfile,
tests and release, and you install and test each one from its own directory
(there are no npm workspaces):

| Path | What | Toolchain |
|---|---|---|
| `/` (the root) | The firewall, `@launchsafe/agent-firewall` | Node 22.13+ (not 23 or 25) to build or test, 22+ to run; npm |
| `browser/` | The browser extension | Node 22.13+ (not 23 or 25), npm |
| `python/` | The Python SDK, `launchsafe-firewall` | Python 3.10+ (tested on 3.10 and 3.13 in CI, 3.14 by hand) |

The root's type check, lint and test runner skip `browser/` and `python/`, and
the npm package never contains them. CI runs the browser checks when their
folder changes, and the Python checks when `python/`, `src/` or `conformance/`
changes (the Python suite replays the conformance vectors against the engine). A change that touches more than one
part passes each part's checks.

## Pull requests and licence

- Open pull requests against `main`.
- Contributions are accepted under the Apache License 2.0 (section 5 of the
  [LICENSE](LICENSE)): unless you say otherwise, what you submit is licensed
  under it.
- Write commit messages in the imperative ("Fix the redirect check", not
  "Fixed" or "Fixes").
- Do not add AI co-author trailers: no `Co-Authored-By` lines for AI tools.

## The firewall (the root)

### The test home

The test suite never touches your own home directory. `vitest.config.ts`
creates a temporary directory and points `HOME`, the XDG directories,
`CLAUDE_CONFIG_DIR` and `LAUNCHSAFE_FIREWALL_HOME` into it; the global setup
refuses to start if anything still resolves to the real home, and every test
file checks again (`test/setup-assert.ts`). Run tests only with `npm test`.

- Start the built CLI from a test only through `spawnCli()` or
  `spawnCliBinary()` in `test/helpers.ts`; they always pass an explicit
  environment inside the temporary root. Lint rejects other ways.
- Give every runtime call a temporary layout or home (`tempHome()`).
- Commands that change the machine call `assertNotRealHome()`
  (`src/runtime/guard.ts`) for every file they write; it refuses the real home
  whenever `LAUNCHSAFE_FIREWALL_TEST=1` or `VITEST` is set.
- Do not run `install`, `uninstall` or `doctor --fix` against your real home
  while developing; use a throwaway `HOME`.

### Maps keyed by outside names

Server, tool, host, client, session, vault and pin names come from outside, and
a plain object answers `map["constructor"]` or `map["__proto__"]` from its
prototype. Read and write such maps with `own()` and `setOwn()` from
`src/own.ts` (or use a `Map`). The `local/own-keys` lint rule
(`eslint.config.mjs`) rejects a computed string key on a string-indexed object;
`test/own-keys.test.ts` feeds those names through the hook, the library and the
gateway.

### Before you hand work back

```sh
npm ci
npm run typecheck && npm run lint && npm test
npm run check:docs          # docs/cli.md matches the CLI specs
npm run conformance:check   # the recorded conformance vectors still match the engine
npm run friction            # gate: 0 interruptions
npm run bench               # gate: p95 < 50 ms, p99 < 150 ms
gitleaks dir .              # secret scan (see below)
```

`test/api/e2e-python.test.ts` runs the Python SDK against the real local API
when `python/.venv` exists (see the Python SDK below, or set
`LAUNCHSAFE_FIREWALL_PY_VENV`); without it, those tests skip and say why.

### Tests that need a sandbox, or a temporary directory that allows exec

Some tests write small stand-in programs (a `curl`, `codex` or `claude` script)
into the suite's temporary root under `TMPDIR`, and the firewall runs or names
them only when they are executable. On a noexec mount (a hardened container's
tmpfs `/tmp`, some CI runners) those tests skip and say why; point `TMPDIR` at
a directory on a mount that allows exec to run them
(`mkdir -p ~/lsfw-tmp && TMPDIR=~/lsfw-tmp npm test`).

The tests of `run` under the OS sandbox skip where there is none: they need
`sandbox-exec` on macOS, or on Linux a root-owned `bwrap` in `/usr/bin`,
`/usr/local/bin` or `/bin` and unprivileged user namespaces, which most
containers' seccomp profiles refuse. The maintainers ran them in a Docker
container (Debian 12, bubblewrap 0.8, seccomp and systempaths unconfined) and
on GitHub's Ubuntu runner (bubblewrap from apt); on macOS they were run by
hand, not in CI while the repository is private. Other hosts are untested.

### The v0.2 upgrade tests

`test/lifecycle/upgrade.test.ts` builds the v0.2 firewall from a git ref
(`v0.2/final`, or whatever `LSFW_V02_REF` names) to test the upgrade path. The
public repository has no v0.2 history, so those tests skip, and the suite names
say why. Maintainers run them locally with the ref before a release.

### Releasing

Releases of the npm package follow [RELEASING.md](RELEASING.md): the checks,
the package-contents review, the publish decision, the tag on `main`, the
one-time setup (a public repository, npm trusted publishing), and the first
version, which a maintainer publishes by hand. Contributors never need to
publish.

## The browser extension (`browser/`)

```sh
cd browser
npm ci
npm run typecheck && npm run lint && npm test   # strict tsc, zero lint warnings, Vitest unit tests
npm run check:vendor   # the vendored scanner files match their pinned firewall commit
npm run build          # esbuild into browser/dist (load it unpacked in chrome://extensions)
npm run e2e:install    # Playwright's bundled Chromium, once
npm run test:e2e       # Playwright end-to-end tests against browser/dist (build first)
```

`npm run check` runs the type check, lint, vendor and public-suffix checks,
unit tests and build together. `browser/src/vendor/firewall/` holds the
firewall's scanner modules, copied at a pinned commit by
`npm run sync:firewall`; do not edit them there. Each end-to-end test starts
Playwright's Chromium headless with a fresh profile in the OS temp directory,
and no request leaves 127.0.0.1. See [browser/README.md](browser/README.md).

## The Python SDK (`python/`)

Google ADK and CrewAI do not install together, so the tests use two
environments. The Pydantic AI extra needs Python 3.11 or later.

```sh
cd python
# everything except CrewAI
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,openai-agents,langgraph,claude-agent-sdk,pydantic-ai,google-adk]'
.venv/bin/pytest && .venv/bin/mypy && .venv/bin/ruff check . && .venv/bin/ruff format --check .

# CrewAI (its tests skip in the first environment)
python3 -m venv .venv-crewai
.venv-crewai/bin/pip install -e '.[dev,crewai]'
.venv-crewai/bin/pytest tests/test_crewai.py
```

`mypy` runs in strict mode (`pyproject.toml`). The tests run a fake sidecar
in-process on a unix socket and on 127.0.0.1, and make no other network calls.
See [python/README.md](python/README.md).

## Secret scanning and the fake fixtures

This is a security tool, so its sources and tests hold secret-shaped strings on
purpose: decoy credentials the firewall plants, values its detectors must catch,
Stripe's published test key and an AWS documentation-style key. None is a real
credential. `.gitleaks.toml` (read automatically by gitleaks) extends the default
rules and allows exactly those, each entry with a comment saying what it is. It
covers all three parts; the browser extension's entries name single files.

Run `gitleaks dir .` (or `gitleaks detect --no-git`) from the root before you
send a change: it must report no leaks. CI runs the same scan on every push and
pull request. Fake values in the conformance vectors carry a visible marker
where the test allows it (decoys contain `LSCANARY`); a value that must look
live (the engine treats anything saying FAKE or EXAMPLE as a placeholder) is
allowed by its exact value in the files that use it. If it flags something new, first work
out whether it is a real secret (then remove it and tell the maintainers) or a
deliberate fake (then add a narrow, commented allowlist entry for that value or
file, never a broad one).
Build output (`dist/`, `coverage/`) is allowed as a whole because it is generated
from the sources that are scanned.
