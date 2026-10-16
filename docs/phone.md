# Phone approvals

> **Experimental, not usable yet.** The hosted relay and approval app that
> phone approvals need are not available, so you cannot pair a phone today.
> **Terminal approvals work now** (see [usage.md](usage.md)).

The firewall half of phone approvals is in this repository and is tested
against a stub relay. The idea: approve or reject a held action from your phone
when nobody is at the terminal, with the approval signed by a passkey on the
phone and verified by the firewall itself against keys pinned in the hook
command. A relay would only carry sealed items and signed decisions; it holds no
key, so neither the relay nor the agent could approve anything.

- Only **approval** items would go to the phone. Proposals (instruction, memory
  and persistence changes) and scope widenings stay in the terminal.
- The passphrase approver stays. A phone is an additional signer, and pairing
  one needs the passphrase. With no phone paired nothing changes.
- The `phone` and `relay` commands exist but are experimental; see
  [cli.md](cli.md).
- The policy keys are in [policy.md](policy.md#phone-approvals-phone).

The wire contract between the firewall and a relay is in
`src/runtime/relay/protocol.ts`.
