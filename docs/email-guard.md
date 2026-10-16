# The email guard

Mail is where outsiders write text your agent reads. A message can carry
instructions a person never sees: Unicode tag characters, a `font-size:0`
span, white-on-white text, an off-screen block with an image that leaks the
conversation. The email guard scans every message a mail tool hands your agent,
withholds the ones that carry hidden instructions, strips hidden padding from
the rest, and keeps a record for you to review. On Claude Code the hook
replaces the result before the model reads it, if the installed Claude Code
honours `updatedToolOutput`; that behaviour is documented but has not been
captured from a real Claude Code (see [limitations.md](limitations.md)).
Behind the MCP gateway the firewall owns the pipe, so this does not depend on
the client. On Codex, Gemini CLI and Cursor the hook runs after the model has
the result, so there the guard warns, records and untrusts the session (see
the table below).

It is deterministic and never uses a model. It sits in front of the existing
taint rule: a mail server's results already make the session untrusted
(`UNTRUSTED_PRIVATE`), so even after a message the guard misses, sending data
out needs your approval, except to destinations you named or allow-listed.

The hosted Microsoft 365 guard and Gmail verification are not part of this
release. Mailbox-side quarantine, when it is built, starts log-only.

## What is built

| Part | Where | Status |
|---|---|---|
| Message parser: RFC 5322 headers, RFC 2047 encoded words, RFC 2231 parameters, multipart nesting to depth 10, quoted-printable and base64, charsets through `TextDecoder`, forwarded `message/rfc822` parts, a 10 MiB cap; structured shapes (generic, Microsoft Graph, Gmail API payloads and `format=raw`) | `src/engine/mail/mime.ts` | built |
| Sender authentication as the provider reported it (SPF, DKIM, DMARC, ARC in `Authentication-Results`), sender notes | `src/engine/mail/auth.ts` | built |
| Detector: every text channel through the shared content scanner, one verdict per message | `src/engine/mail/detect.ts` | built |
| Read-path filter and message splitter (stubs, stripping, whole-result withholding) | `src/engine/mail/filter.ts` | built |
| Hooks integration for MCP mail tools: Claude Code, Codex, Gemini CLI, Cursor | `src/runtime/mail/guard.ts` (called from `src/hook/pipeline.ts`), `src/hook/claude.ts` | built |
| Quarantine store and review CLI (`mail quarantine`, `release`, `discard`), `mail audit` over saved mail | `src/runtime/quarantine.ts`, `src/mail-cli.ts` | built |
| `mail_quarantined` notification, `status` count, `doctor` check, FW-MAIL-WITHHELD | | built |
| False-positive corpus and the `npm run mail-friction` gate | `src/mail-corpus.ts`, `scripts/mail-friction.mjs`, `test/fixtures/mail/` | built |
| Mailbox-side decision (log/enforce) | `src/engine/mail/mailbox.ts` | decision built; moves not built |
| The filter inside the MCP gateway (every client, hooks or not) | `src/gateway/pipeline.ts` (`mailGuard`) | built: the gateway calls the same guard on a mail server's `tools/call` results before its own scan |
| `mail serve` (LaunchSafe's own read-only mail MCP server: IMAP, Graph delegated) | `src/runtime/mail/types.ts` (interfaces) | later |
| Mailbox quarantine (IMAP IDLE/MOVE, Graph delegated delta/move), `mail guard`, `mail login`, `mail audit --account` | `src/runtime/mail/types.ts` (interfaces) | later |
| Hosted Microsoft 365 guard, Gmail public app | LaunchSafe's hosted service, not this repository | later |

This build never sends or fetches mail. Everything runs on what a mail tool
already returned to your agent, or on files you point `mail audit` at.

## How a message is judged

Every channel a model could read is scanned with the shared content scanner
(`src/engine/content-scan.ts`): the subject, the whole From header (decoded),
Reply-To, the address headers (To, Cc, Bcc, Sender, Resent-*, display names
included), every other header, each MIME part's own header fields
(`Content-Description`, `X-` fields, every `Content-Type` parameter), header
lines that are not fields, a leading mbox `From ` line, and the MIME preamble
and epilogue (no mail client displays these, but a model reading the raw
source or a header list does: a phrase there addressed to an AI agent is hidden
text with an instruction, unless it copies displayed text, as Exchange's
Thread-Topic copies the subject; a header block of more than 2,000 fields was
not fully read, `scan_incomplete`), the provider's preview (`snippet`,
`bodyPreview`), text and HTML bodies (Microsoft Graph's `body` and
`uniqueBody`; every alternative: AMP `text/x-amp-html` and watch HTML parts
are read as HTML, and any other inline `text/*` part as text; a body whose
type is not declared, such as a `body` string, is read as text and, when it
has any markup, as HTML too, so a hidden element under any tag is read as
hidden), text attachments (`text/*` parts, attached or not), base64 attachment
content in a structured message (Graph's `contentBytes`, a Gmail attachment
part's `body.data`, decoded; in exactly two places, Graph's
`attachments[].contentBytes` and the `body.data` of a Gmail part that has a
`filename`, other than a calendar (a Graph forwarded message is kept too; a
Gmail `message/rfc822` part with a `filename` is an attachment like any
other, so the placeholder applies to it), content over 1 MiB of
base64 is not read and is replaced in the result by a placeholder the
firewall writes, so a large attachment neither withholds the message nor
reaches the agent unread; base64 that large anywhere else, such as the
`body.data` of a Gmail body part with no `filename` or an attached calendar,
is not replaced: it is decoded and read as the body (or the calendar or
message it is), and past the scanner's bounds the message was not fully read
and is withheld on the read path),
calendar parts (every property: `SUMMARY`, `DESCRIPTION`, `LOCATION`,
`COMMENT`, `CONTACT`, `CATEGORIES`, `RESOURCES`, `URL`, `ORGANIZER` and
`ATTENDEE` with their `CN` names as displayed text, `X-ALT-DESC` and any
`FMTTYPE=text/html` value as HTML, and every other property, parameter and
`X-` property as text no client displays; a part of more than 20,000 lines was
not fully read, `scan_incomplete`), attachment names and types, and forwarded
messages recursively. The signals are merged and one verdict is given:

- **withheld** (`quarantine`) when any of these fire (the `emailGuard.quarantineOn` names):
  - `tag_chars`: Unicode tag characters with readable text (a complete England,
    Scotland or Wales flag is an emoji, not smuggled text);
  - `hidden_instruction`: CSS-hidden text (not a copy of visible text) with a
    phrase addressed to an AI agent or an imperative such as "forward ... to".
    Styles are read as a browser reads them: CSS comments are dropped and CSS
    escapes decoded, so `display:/**/none` and `displ\61 y:none` hide, and a
    selector's identifier escapes too (`.\78{display:none}` hides class `x`).
    Hiding counted: `display:none`, `visibility:hidden`, the `hidden`
    attribute, `mso-hide:all`, a font under 1px (or of 1px with
    `line-height:0`), near-zero opacity, a box of 1px or less that clips its
    overflow, `transform: scale(0)` (or any scale that leaves a glyph under a
    pixel), `translate`/`translateX`/`translateY`/`translate3d` (or the `translate`
    property) of 1000px or more either way or of -100% or less, zero clipping,
    off-screen positioning, text-indent, low contrast,
    Outlook-only conditional copies, `<template>`, comments, and the
    `<title>` (never shown by a mail client; counted when its text addresses
    an AI agent and copies neither visible text nor the message's subject,
    which is the default title of newsletter tools; a lone "ignore previous"
    in a title is not enough). Rules in
    `<style>` blocks apply through type, class, id and attribute selectors
    (`div[data-a]`) with descendant and child combinators; client hacks keyed
    on attributes the client adds (`[data-ogsc]`, `[x-apple-data-detectors]`)
    match nothing, and pseudo-class and sibling selectors are not modelled;
  - `dense_zero_width_instruction`: dense zero-width characters (eight or more,
    or four in a row; one on its own is ordinary) within 200 characters of text
    addressed to an AI agent, before or after it (every place such text
    appears counts, not only its first);
  - `hidden_exfil_link`: a hidden image or link whose URL templates data or
    goes to a capture host;
  - `auth_fail_instruction`: the provider says the sender failed
    authentication **and** the message addresses an AI agent.
  - On the read path, also a message that could not be fully read
    (`scan_incomplete`: over 10 MiB, nested too deep, a scanner bound;
    `scan_failed`). You can release it. The scanner's bounds count work
    rather than time: 4 MiB of text or 2 MiB of HTML per part, 50,000 HTML
    nodes, 2,000 CSS rules, and 4,000,000 style-matching steps per part
    (`css_work`; a class looked up, an attribute value read and an ancestor
    compared each count, so one element with a huge class list or a
    megabyte attribute cannot hide work inside a single step). On top of
    those, each message has one work budget of 64,000,000 units (a unit is a
    character read, a style-matching step, or 64 characters searched when
    hidden text is compared with the visible text), shared by all its parts
    and channels, forwarded messages included. The text no client displays
    (other headers, MIME preambles) is compared with the message's displayed
    text, and that displayed text is paid for once per message, however many
    forwarded levels each bring a header block. Once the budget is spent the
    remaining parts are not read: they are reported incomplete (`work`) and
    the message is withheld. The rewriting pass that strips hidden text reads
    the same text again, so it has a second budget of the same size rather
    than being charged for the scan's reading. A message of thousands of parts
    therefore costs no more than its two budgets, a few seconds of work at
    most, and every message of our mail and content corpora uses well under
    an eighth of one. One tool result has a total of four budgets
    (256,000,000 units), shared by every message's scan and rewriting pass
    and by the text outside or past its messages: each pass draws its budget
    from what is left of the total, so once the total is spent the messages
    after it are not read and are withheld (`scan_incomplete`, `work`), and a
    result of hundreds of messages costs no more than four. Ordinary
    listings stay far inside it: a unit is about one character read, every
    message of the false-positive corpus costs at most 55,000 units (median
    2,440), its 435 messages listed 50 or 100 to a result cost at most 2
    million units per result, and a listing of 100 HTML newsletters of
    130 KB each costs about 13 million, so none of them loses a message to
    the cap (printed by `test/mail/review-r7.test.ts`, which asserts only that
no ordinary message is lost to the cap). On the mailbox
    path a message past the cap is not withheld, but its text is replaced
    by the "could not be fully scanned" note rather than passed on unread,
    and a message whose scan failed (`scan_failed`: a part could not be
    listed or scanned) is replaced whole by that note. The same holds for
    text that is not a message there: a result that could not be split into
    messages is rewritten when its scan could not read it all and replaced by
    the note when its scan failed, a piece of text outside the messages is
    replaced by the note in either case, what lies past the splitter's
    bounds is rewritten, and the whole result is replaced by the note when
    the scan of what lies past those bounds failed, or the scan of the pieces
    of text outside the messages past the first 5,000 failed or could not
    read them all. What lies past the splitter's bounds, and a result that
    could not be split at all, is read by its scan only up to 200,000 strings
    or 32 MiB of text. On the read path a result with more is withheld whole
    (`scan_incomplete`); on the mailbox path the tail past that is treated
    like text the scan could not read: in both cases (split or not) the piece
    the bound cuts, and every piece after it, is replaced by the note, and
    only what the scan read is rewritten and passed on. (On the read path a message whose scan failed is withheld; once you
    release it, it is delivered like any released message, below. A message the
    firewall could not read at all has no fingerprint, so there is nothing to
    release: `mail quarantine release` refuses it and says to discard it.) The rewriting
    pass also stops at 20 levels of nesting inside a message: a string, or a
    whole object or list, deeper than that is replaced by the "could not be
    fully scanned" note, never passed on unread. Object keys are text like
    values: the scan reads every key that is not a plain token (in a message,
    through the catch-all channel below; outside the messages, piece by
    piece), and the rewriting pass strips a key's hidden parts like a value's.
    A key the rewriting pass could not read is replaced by a placeholder the
    firewall writes (`[key withheld 1]`, numbered within its object), and so
    is a stripped key that would otherwise take the place of another key of
    the same object. The rewriting pass reads a string as HTML whenever it
    has any markup or character reference (`<` followed by a letter, `!`,
    `/` or `?`, or `&#`), so it
    strips at least what the scan found hidden, whatever the tag (a
    `<section style="display:none">` in an `html` field), and a raw source
    under any of the keys the parser reads one from (`raw`, `source`,
    `rfc822`, `mime`, `eml`) is rendered as its readable parts. The hook's input (the event
    on standard input) is read up to 64 MiB; a larger event is not read. Before
    a tool runs, the hook then blocks the action with that error; after it ran
    (PostToolUse, where mail results arrive) there is no action left to block
    and the hook cannot withhold the output: an oversize result reaches the
    agent unscanned (the session is still untrusted by the taint rule).
    Because these bounds count work, the same message gets the same verdict
    every time, on any machine. The one exception is the last-resort clock
    (2 seconds per part): the counted bounds keep a scan well inside it, but
    on a badly overloaded machine it can still cut a part short, and that
    part is then withheld (`time`). So on the read path a verdict can
    differ between runs only by withholding a message that another run
    delivered, never the other way round (on the mailbox path an
    incomplete scan never moves mail, so there it can only leave a message
    in place). On a delivered message, a string the rewriting pass
    could not fully read is replaced by a note rather than passed on
    half-cleaned, and a message whose rewriting runs out of its budget is
    withheld as a whole. A notice for something withheld only because it
    could not be fully scanned says so (the work limit, a size bound); it
    does not claim the text addresses an AI agent.
- **neutralized** when there is hidden text with nothing directed in it (a
  marketing preheader, zero-width padding): it is stripped and the message
  delivered.
- **flagged** when visible text addresses an AI agent (a security newsletter
  quoting "ignore previous instructions"): delivered unchanged, with a note to
  the agent to treat it as data.
- **delivered** otherwise.

Sender authentication: only the top-most `Authentication-Results` header whose
authserv-id is the provider's (`mx.google.com`, `*.prod.outlook.com`,
`*.protection.outlook.com`, `mx.microsoft.com`, `*.mx.microsoft`, plus
`emailGuard.authservIds`)
counts. A sender can write any such header into its own message, but it sits
below the provider's and cannot replace its verdict. Microsoft 365's Exchange
Online writes its header with no authserv-id: when Microsoft's own
`ARC-Authentication-Results` is present, the first id-less header (Exchange's)
and Microsoft's top-most ARC result are the verdict, so a forged
`mx.google.com; dmarc=pass` lower down or a forged ARC result with a higher
`i=` does not override Microsoft's failure. Exchange's header has no `arc=`
result of its own: Microsoft's top-most ARC result saying `arc=pass` on a chain
sealed by a mailing-list host cancels Exchange's DMARC failure, as it does any
provider's; a lower, sender-written ARC result does not. With no provider
`Authentication-Results`, the provider's `ARC-Authentication-Results` are read
(the top-most and the lowest instance). Headers a sender wrote can add a
failure, never remove one. Failure is `dmarc=fail`, or `spf=fail` with no
passing DKIM. A passing ARC chain sealed by a mailing-list host
(`googlegroups.com`, `groups.io`, public list servers, see `ARC_FORWARDERS`)
cancels it; a seal by the sender's own domain or a mailbox provider does not.
Unknown authentication never fires the rule. Display names that name another
domain, Reply-To on a different registrable domain, punycode and mixed-script
domains are reported and never withhold alone.

## On the agent's read path (the hooks)

After an MCP tool runs, the hook pipeline hands its result to the guard when
the server is mail: its name matches `mail|imap|gmail|outlook|smtp|e-?mail`
anywhere (plugin prefixes ignored, so Claude's own Gmail connector counts), or
has `m365`, `o365`, `jmap`, `inbox`, `mailbox` or `exchange` as a whole word
(any case; words split at punctuation and camelCase, so `ms-exchange`,
`SharedInbox` and `fastmail-jmap` count and `inboxer` or `sandbox` do not), or
`emailGuard.servers` lists it. The tool's own name counts the same way, for a
server named after its vendor (`microsoft` with `outlook_list_messages`).

Two choices about false positives. `exchange` next to a market word (`rates`,
`currency`, `fx`, `crypto`, `coin`, `stock`, `price`, `market`, `trade`,
`token`, `swap`, ...) is not mail, so `exchange-rates`, `crypto-exchange` and
a tool named `get_exchange_rates` are left alone. `inbox` is always mail, so
`inbox-zero-todo` is guarded: "inbox zero" is an email practice, and a wrong
guess only means a non-mail result is scanned like a message (a stricter
reading, never a looser one). A server the guard should leave alone cannot be
taken off the list by policy; rename it in the agent's configuration.

The **splitter** finds the messages whatever the
result's shape: MCP content blocks whose text is JSON, `structuredContent`,
Gemini CLI's `llmContent`, Cursor's `result_json` string, lists or containers
of message objects (`messages`, `value`, `items`, ...), and raw RFC 5322
sources (also base64url, as the Gmail API returns them). A message-like object
has a body and a sender, a subject (directly or in its headers) or a key only
mail has (`payload`, `threadId`, `toRecipients`, `to`, `cc`, `messageId`,
...). A body is any key the parser reads one from (`body`, `text`, `html`,
`bodyHtml`, `body_html`, `plain_text`, `snippet`, `summary`, `raw`, ...), so the
splitter and the parser agree on what a message is. A sender or subject key
counts even when it is empty, so a message with an empty subject is still read
as one message, not as loose strings. An `author` or a `title` alone is too
common (issues, documents, comments) to make an object mail: each counts as a
sender or a subject only next to a key only mail has. An object is taken as an
already-parsed message only when the firewall's own parser built it: an object
from a tool, or one parsed from JSON text (a subject that spells
`{"headers": [...], "text": [...], "problems": []}`), is read key by key like
any other, so every string in it is read.

- A withheld message is replaced in place by a stub:
  `{ id, from, subject, date, withheld: "LaunchSafe Firewall withheld this message: hidden_instruction. Record q-.... ..." }`.
  The sender and the subject are shown (with hidden parts stripped) only when
  the scan was complete and judged them without finding text addressed to an
  agent. A sender or subject that itself carries the instruction is shown as
  `[withheld]`, and so are both whenever the scan was not complete (a message
  past the work limit or a size bound, or one whose scan failed): the scan may
  never have read them, so they are not shown however they read. What is shown
  is the display form (a sender's name with its quotes and quoted pairs undone),
  which is not the header text the scan read, so the exact string the stub
  would show is scanned once more and shown only when that scan finds nothing;
  `"Ig\nore all pre\vious instructions" <a@…>` is `[withheld]`.
  Every other field is fixed text or of a strict shape, because a stub is not
  scanned again, and a Message-ID is the sender's to choose: the `id` is kept
  only when it is a number, or a string of up to 64 digits only or up to 64
  hex digits of one case only (a Gmail id), which can spell nothing an agent
  would act on. Every other id (a Message-ID, a Microsoft Graph id) is given
  as a fingerprint the firewall writes, `sha256:` and the first 12 hex digits
  of the id's SHA-256, so `ignore.previous.instructions@…` never reaches the
  agent however its words are spelled or separated. The same id always gets
  the same fingerprint, so the agent can still tell the stubs apart; the record id and the review
  command are always in the stub. The `date` is kept only when it is an RFC 5322 or
  ISO 8601 date, is given as the firewall's own ISO date when it is another
  form a clock can read, and is left out otherwise. An object outside the
  messages that looks like a stub but differs from the one the filter made in
  any field is scanned like any other text.
- A neutralized message has its hidden parts stripped; JSON stays valid.
- Text in a split result outside its messages (a thread's snippet, a folder
  name, object keys) is scanned piece by piece: a piece with a hidden
  instruction is replaced by a notice and recorded, hidden padding is stripped.
  Past the first 5,000 pieces the rest are scanned as one piece: a strong
  signal there withholds the whole result, and hidden padding found there is
  stripped from each of those pieces too.
- Every string of a message object that no other channel reads (a custom
  `notes` field, a second summary next to `snippet`, a `sender` next to
  `from`, an attachment's `description`, `content` or content type, a body
  object's other keys, a header entry's other properties, the other fields
  next to a `raw` source, object keys, however deep) is read by a catch-all
  channel and scanned like text, so a delivered message cannot carry an
  instruction in a field only the model reads. The same withhold, strip or
  flag result applies to the whole message. Plain tokens are skipped: numbers,
  hex ids, dates, and short tokens of letters with no space and no `_`, `-` or
  `%` (an address, a folder name like `INBOX`, a URL); a token that joins words
  with `_`, `-` or `%` (`Ignore_all_previous`) or runs more than 32 letters
  and digits together is scanned. Past 500 such fields the rest are scanned as
  one piece. Base64 (a Gmail `body.data`, Graph's `contentBytes`) counts as
  read once decoded only when it decodes whole (only the alphabet, padding only
  at the end); anything after a `=` or outside the alphabet is read as it is by
  the catch-all too. The catch-all reads at most 200,000 values and 16 MiB of text
  per message; a message with more was not fully read (`scan_incomplete`,
  withheld on the read path). A message object the parser cannot read at all
  (it fails on it) is withheld with `scan_failed`, and so is a message whose
  forwarded message could not be parsed.
- The splitter rewrites up to 500 messages and 12 levels of nesting. What lies
  past either bound is not split: it has its hidden parts stripped and is
  scanned as one piece, and a strong signal withholds the whole result (fail
  closed). On the read path the messages past the bounds are still found and
  scanned one by one (decoded, as any message), each on the result's work
  total, so once that is spent they are withheld; only the text around them
  is the one piece, and nesting deeper than 1,000 levels withholds the whole
  result (`scan_incomplete`). When stripping the text past the bounds runs
  out of its budget, the strings it could not pay for would be the note, so
  on the read path the whole result is withheld instead (`scan_incomplete`,
  `work`), as a message whose rewriting runs out is. On the mailbox path a
  message the parser could not fully read for any bound (size, nesting, parts,
  fields) carries a `scan_incomplete` signal, so it is rewritten (and noted),
  never passed on as it was. The record's note names the bound ("more than
  500 messages", "nested deeper than 12 levels"). A result with more strings
  than can be read (200,000, or 32 MiB of text) is withheld with
  `scan_incomplete`.
- A result the splitter cannot read as messages is scanned whole; a strong
  signal withholds the whole result, and the record says the split was not possible.
- JSON text is delivered as it came only when it is exactly its parse written
  out again. `JSON.parse` keeps the last of two equal keys, so a text such as
  `{"body": "<hidden instruction>", "body": "Hello"}` holds a value no parse
  shows; and the parser trims more than JSON's own whitespace (a byte order
  mark, a no-break space). A JSON text the splitter parses is delivered as it
  came when `JSON.stringify` of its parse gives the same text but for the
  whitespace between tokens; otherwise it is delivered as its parse, serialized
  again (two-space indented), which is exactly what was scanned. Serializing
  again changes the layout and can change how a value is written: an integer
  past double precision (`12345678901234567890` becomes
  `12345678901234567000`), `1.0` as `1`, an escape as the character it stands
  for; it never adds text. A text with repeated keys, or with other characters
  than JSON's whitespace at its edges, counts as stripped, so a hook that can
  replace the output hands back the rewritten result. The values a repeated
  key shadows are also scanned, as one piece: an agent whose hook cannot
  replace the output (Codex, Gemini CLI; the firewall does not replace output
  on Cursor) reads the text as it came, so a hidden instruction there is
  withheld and recorded like a message ("values a repeated key hides in a JSON
  text"), and that agent is warned. Where JSON text
  is delivered as it is (a result that could not be split, a JSON text no pass
  parsed), such a text is also read as the text it is.
- Text that starts like JSON (`{` or `[`) but does not parse (cut short, text
  after it) is read as text, and, on the read path, the backstop also reads its
  string literals with their escapes undone: an agent decodes `󠁁`
  as a tag character, though the text as it is holds only letters.
- **The structural backstop.** Once the result the agent would get is fully
  built, every string and object key in it (JSON text parsed, as the splitter
  parses it) is scanned once more, except text the firewall wrote itself
  (stubs, notices, the "could not be fully scanned" note, `[key withheld N]`,
  the attachment placeholder), the rewritten output of a message the person
  released (it is theirs to see), and strings that can spell nothing
  (numbers, hex ids, dates). The skipped firewall texts are fixed strings
  matched exactly: a string that only resembles one (the note with anything
  added) is read like any other. A string is read the way the passes read
  text of unknown type: as HTML when it looks like HTML, otherwise as text,
  and as HTML too when it has any markup. A string with a hidden instruction
  there (a `quarantine` verdict), or a walk that cannot finish (a work budget
  of its own the size of a result's total, 256,000,000 units; 1,000,000
  values, 64 MiB of text, 2,000 levels of nesting, or the result's deadline,
  below), withholds the whole result: it is recorded ("a final check of
  the whole result ...") and replaced by a notice. A string with hidden parts
  no pass stripped (a `neutralize` verdict) is replaced by its stripped text,
  and the result counts as stripped. When the stripped text still does not
  scan clean, the whole result is withheld, and the record gives the reason
  that holds: a hidden instruction, or hidden characters the stripping could
  not remove (`scan_incomplete`, "hidden characters the firewall could not
  strip"); a text the person released (`mail quarantine release`) is delivered
  as it is.
  A raw message source the passes read part by part and delivered as it was
  is read by the backstop only as one whole string: its headers, its parts
  still encoded (base64, quoted-printable) and its MIME boundaries together,
  out of the parts' context. A hidden instruction found there still withholds
  the result, but what that whole reading would strip is not stripped (read
  whole, a Persian part's zero-width non-joiners or an Arabic part's direction
  marks would look hidden); the source is delivered unchanged, as the parts'
  own reading judged it.
  Content blocks reach the agent joined, so their joined text is read too
  (once, in pieces of 512 Ki characters that overlap by half, so anything up
  to 256 Ki characters long lies whole in one piece): a hidden element or
  phrase split across two blocks withholds the result, however much padding
  stands between the two halves inside that bound. Only what joining adds
  counts: when the joined text withholds, each block is read alone, and only
  when none withholds alone is the result withheld. When one does (a message
  the person released, or JSON text the walk read as its parse), each
  boundary is read with 32 KiB on each side, joined and alone, instead.
  Content blocks are MCP `content` blocks of type `text` (also as a bare list,
  as Claude Code passes them) and Gemini CLI's `llmContent` parts; any other
  list of objects with a `text` field is JSON the agent reads as such, and one
  block has no boundary. Visible text addressed to an AI
  agent in a result where nothing was flagged gets the flag note. A provider's
  preview (`snippet`, `bodyPreview`, `summary`, the keys the parser reads a
  preview from) cut inside a flag emoji has the cut tail dropped first, as the
  detector drops it; no other string is trimmed. Text every pass read and
  cleared scans the same again, so on ordinary mail this costs time only (the
  tests log the time a result of 200,000 short strings and one of 5,000
  content blocks take, and assert only a generous bound, 15 seconds); it holds
  the rule "nothing reaches the agent unless a pass read that exact text" even
  where a pass has a gap. That rule holds for what the guard hands back: on
  an agent whose hook cannot replace the output, and for a hook event too
  large to read, the agent has the result as the tool returned it. Read path only; `emailGuard.readPath: "log"` reports
  what it would withhold.
- **One deadline per result.** On the read path the whole filter, every pass
  and the backstop together, has 20 seconds of wall-clock time from the moment
  it starts (`deadlineMs`), well inside the hook's own timeout (600 s for Claude Code and Codex, 60 s
  for Gemini CLI, 30 s for Cursor), so a
  result too slow to check is withheld by the firewall (`scan_incomplete`,
  `time`; one record for the whole result) rather than handed over unchecked by
  an agent that stopped waiting for the hook. The deadline is looked at
  between messages and between strings (before each scan), not inside one: a
  scan in progress can run up to its own 2-second limit past it. So the
  clock can change a verdict only toward withholding, and only while the hook
  finishes: the work bounds keep an ordinary result far inside 20 seconds,
  but a hook killed at its own timeout hands nothing back, and what
  happens then is the agent's choice (Cursor's entries are fail-closed, and
  most other agents carry on with the result as the tool returned it). The hook calls the
  guard from `src/hook/pipeline.ts`.
- The filter never throws. A result it cannot filter is withheld whole
  (`scan_failed`); when the record of a withheld piece cannot be saved (the
  store fails), the piece is still withheld and its notice says the record
  could not be saved.
- The session gets a taint source naming each record
  (`mail from gmail withheld: hidden_instruction (record q-...)`), a
  `mail_scan` log entry with rule FW-MAIL-WITHHELD, and you get the
  `mail_quarantined` notification ("N messages were withheld from your agent").

What each agent allows:

| Agent | Hook | What the guard can do |
|---|---|---|
| Claude Code | PostToolUse (`updatedToolOutput`) | replaces the result (relies on `updatedToolOutput`, not yet captured live; if ignored, the model sees the message and the session is only marked untrusted) |
| Codex | PostToolUse | cannot replace output: the model is told which messages carry hidden instructions and to treat them as data; the session is untrusted; record and notification |
| Gemini CLI | AfterTool | same as Codex |
| Cursor | afterMCPExecution | the firewall does not replace output on Cursor, and adds no context there: record, untrusted session, notification |

On Codex, Gemini CLI and Cursor the model has already read the message when
the hook runs. The guard cannot take that back; what it guarantees is that the
session is untrusted, so anything the agent then tries to send, any message,
any change to its instructions or settings needs you. The MCP gateway removes
this limit for every client, because it owns the pipe: wrap the mail server with
`launchsafe-firewall mcp wrap-config` and withheld messages arrive as stubs,
whatever the client.

`emailGuard.readPath: "log"` records what enforce would do in the log and
tells you; it saves no quarantine record, withholds nothing, and still marks
the session untrusted.

## Reviewing and releasing

```
launchsafe-firewall mail quarantine            # the review list (read-only; agents may run it)
launchsafe-firewall mail quarantine show <id>  # sender, subject, auth, why, the hidden text escaped (your own terminal only)
launchsafe-firewall mail quarantine release <id>
launchsafe-firewall mail quarantine discard <id>
```

Records keep ids, sender, subject, the provider's authentication summary, the
signals, the message's sha256 and a 200-character escaped preview of the
hidden text. Never the message: it stays in your mailbox; nothing is deleted.

The list is read-only and an agent may run it, so it prints no hidden-text
preview (not in `--json` either) and says that the senders and subjects it
shows are text outside senders wrote, data rather than instructions. `show`
prints what was withheld from the agent (the Message-ID and the hidden text
too), so like `release` it runs only for a person in their own terminal; the
engine refuses it from inside an agent (FW-TAMPER). It shows only the email
guard's records: a record of the MCP gateway (which keeps the withheld text
itself) is shown only by `gateway quarantine show`, never by a mail command.

`release` is the human channel: it runs only in your own terminal (not under an
agent; the engine also refuses it from inside one, FW-TAMPER), shows you the
escaped preview of the hidden text the scan found, needs the approval passphrase when one is set (it signs the
release with your approver key, and the hook honours only releases signed by
the key pinned in its command), and asks for "yes". The released message is
then delivered with its hidden parts stripped. That holds for a message
withheld because it could not be fully scanned too (`scan_incomplete`,
including the work limit): its rewriting pass gets a fresh budget, and any
string that still could not be fully read is shown as a "could not be fully
scanned" note rather than passed on unread. The rest is delivered, because you
chose to release it. Such a message has no hidden-text preview, or only part
of one, because it was never fully read: `show` and `release` say so plainly,
and releasing it gives the agent text the firewall never fully checked.
`discard` closes the record; the message stays withheld. Phone approvals do
not release mail: release needs the record (and any hidden-text preview) in
front of you.

## Measuring false positives

`npm run mail-friction` is the release gate. It fails when any template,
newsletter, multilingual, mailing-list, calendar or ordinary message is
withheld, when a pinned verdict changes, or when any attack fixture is missed,
and it runs the corpus through the splitter as tool results of 20 messages.

The corpus (`src/mail-corpus.ts`): the shared scanner's fixtures (open-pattern
templates written for this repository, LaunchSafe's own transactional mail,
ham, multilingual text, newsletters, list posts, calendar text, 33 attack
payloads), each wrapped as four messages (MIME alternative; single-part, with
legacy charsets for multilingual text; forwarded inside another message;
Graph or Gmail API JSON), plus `test/fixtures/mail/` (the acceptance
messages, the false-positive table, legacy charsets, forwarded chains,
digests, attachments, sender notes, and mail-specific attacks through every
channel). Attack payloads are benign markers (LSTEST).

Numbers as last measured (regenerate them with `npm run mail-friction` before
a release): 591 messages, 435 non-attack messages with **0
withheld**; 169 neutralized (hidden padding stripped, reported, not a false
positive) and 20 flagged; attack recall **156/156** across tag characters,
hidden HTML, hidden exfiltration links, zero-width and auth-failure families.

Not in the corpus yet: the SpamAssassin ham set, public
list archives and 150 open-source templates, which need downloads and
per-file licence checks. Known misses by design: paraphrased instructions that
use no lexicon phrase, languages other than English, text in images, and the
contents of binary attachments (PDF, Office, images) beyond their bytes read
as text: text attachments and base64 content in structured messages are read
(see above), but a document's compressed text is not extracted.

On your own mail, without anything leaving the machine:

```
launchsafe-firewall mail audit --path ~/Mail/export.mbox   # or a folder of .eml files
launchsafe-firewall mail audit --path ~/Mail --json         # counts only: no addresses, no subjects
```

It reads at most 5,000 messages by default (`--limit N` changes that). It
prints counts per verdict, reason and signal, and the file and position of
withheld messages. If you judge one benign, it is a false positive worth
reporting; it becomes a fixture and the rule is fixed before release.

## Policy (`emailGuard`)

See [policy.md](policy.md#the-email-guard-emailguard).

## Honest limits

- **On Codex, Gemini CLI and Cursor the model has read the message** before
  the hook runs. The guard warns, records and untrusts the session; only Claude
  Code's hook, and the MCP gateway for any client behind it, can keep the
  message from the model.
- **Claude Code's withholding relies on `updatedToolOutput`**, which Claude
  Code documents but which has not been captured from a real Claude Code (see
  [limitations.md](limitations.md)). If a version ignored it, the model would
  see the message and the session would only be marked untrusted.
- **Variation-selector smuggling is not a quarantine reason.** Through the
  gateway such a result is withheld; through Claude Code's hook the characters
  are marked and the session is untrusted; with other agents only the session
  is untrusted (FW-HIDDEN-OUTPUT).
- **MCP mail tools only.** Mail an agent reads another way (a shell command
  that prints a mailbox, a file it opens, a vendor's cloud connector the hook
  never sees) is not split into messages. The taint rule still applies to what
  those tools bring in.
- **Shape guessing.** A mail server with an unusual result shape may not split;
  then the whole result is scanned, and a strong signal withholds all of it.
- **Attachments' contents are not scanned** (PDF, DOCX, images); their names are.
- **English lexicon only**. Hidden-text rules are language-independent.
- **Sender authentication is what the provider wrote.** No signature or DNS
  check is made; the rule applies to the top message only, not to forwarded
  ones.
- **Mailbox-side quarantine is a race** when it lands (E2): a message is moved
  after it arrives. It will start in log mode.
