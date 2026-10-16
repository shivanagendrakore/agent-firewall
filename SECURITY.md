# Security policy

This policy covers everything in this repository: the firewall at the root (the
CLI and agent hooks, the library, the MCP gateway, the email guard and the local
API), the browser extension in `browser/` and the Python SDK in `python/`.

## Reporting a vulnerability

Email **security@launchsafe.com** with a description and, if possible, a
reproduction expressed as **actions and outcomes** (the recorded hook input and
the decision you expected versus what happened) rather than a working exploit
against a third party. Please do not open a public issue for an unfixed bypass.

We will acknowledge within three business days, and we aim to give a status
update within 14 days. Coordinated disclosure is appreciated; we will credit
you unless you prefer otherwise.

There has been no third-party security audit.

## What a report should show

This project's job is to make the firewall's **decision** correct. The most
useful reports are:

- a command, tool call, or sequence the firewall **allowed** that should have
  been denied, queued or asked (a bypass);
- a path to writing a protected file, reading a credential store, or sending
  data out that the classifier misses;
- a way to make the firewall **fail open** (crash, timeout, parse error, or race
  that results in `allow` for a risky action) beyond the hook-timeout cases
  documented in [docs/limitations.md](docs/limitations.md);
- a way to tamper with the decision log without `log verify` catching it;
- a concurrency bug that loses or corrupts state;
- in the browser extension, a way for a page or a hijacked browser agent to buy,
  send, grant, upload or move private data without the approval it is meant to
  need, within the limits in its threat model;
- in the Python SDK, a failure (an error, a timeout, a malformed answer) that
  lets a tool call run without an `allow` from the firewall.

Each of these maps to a test we will add, so a fix comes with a regression test.

## Scope and expectations

- The firewall is an enforcement layer, **not a sandbox**. Reports that depend on
  a command the firewall legitimately allowed then doing damage the OS sandbox
  would have contained are design limitations, documented in [docs/limitations.md](docs/limitations.md), not
  vulnerabilities in the firewall. We still want to hear about new **action
  classes** that should be constrained.
- Known, documented limits (`@`-included files not passing through `PreToolUse`;
  a repo's `disableAllHooks` without managed settings; files read before
  installation) are in [docs/limitations.md](docs/limitations.md). A report that these exist
  is not a new finding; a report that **managed settings do not actually resist
  them**, or that a documented limit is worse than stated, is.
- No LaunchSafe telemetry: nothing about you or your work is sent to
  LaunchSafe. That is not the same as no network use. What uses the network,
  by component:
  - `update`, run by a person: GETs OSV's public malicious-package exports
    (nothing is sent). It is the only command that downloads data without a prompt (`doctor --fix` offers the same download after you confirm).
  - The hooks' decisions: no network calls, unless you pair a phone
    (experimental; the hosted relay is not available yet), in which case the
    relay daemon carries sealed items and signed decisions to LaunchSafe's
    relay.
  - The MCP gateway: relays your MCP client's own traffic to the servers you
    configured, and `mcp login` talks to their authorization servers.
  - `run`: a local proxy that carries the sandboxed program's own connections
    to the hosts your policy admits.
  - `openshell serve`: answers OpenShell's gateway on the address you give it.
  - The local API (`serve --api`): a unix socket or a loopback port only.
  - The dashboard (`ui`): 127.0.0.1 only, loads nothing from the network.
  - `log anchor --exec`: runs the upload command you give it.
  - The browser extension makes no requests of its own; the only requests it
    causes are ones the person approves (re-downloading a held file, reopening
    a held address). The Python SDK talks only to the local API it is pointed
    at.

  A report that any part sends data anywhere else, or that a decision contacts
  the network without a paired phone, would be a serious bug — please flag it.

## Supported versions

Pre-1.0: only the latest version of each part is supported. After 1.0 we will
support the current and previous minor versions.
