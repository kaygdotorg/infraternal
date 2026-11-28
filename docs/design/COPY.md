# COPY.md: product UI copy guidelines (proposal)

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

> **Status:** Proposed for owner review (#598, 2026-11-27). Not yet adopted.

Every word in the interface is part of the product. Good UI copy reads like a
calm, competent colleague telling you what happened and what you can do next —
not a chatbot, not a manual, and not a marketing page.

This document summarises well-regarded primary sources on product UI writing,
records their current links and quoting/reuse licences, proposes a short
checklist for infraternal, and shows ten before/after rewrites of real strings
currently in the app.

---

## 1. Reference sources (links and licences verified 2026-11-27)

### Style guides (online)

| Source | Current URL | Licence / quoting notes | What it is best for |
|---|---|---|---|
| **Apple Human Interface Guidelines — Writing** | https://developer.apple.com/design/human-interface-guidelines/writing | Proprietary copyright (Apple Inc.). Link and paraphrase; do not copy bulk text. | Concise button verbs, platform-native phrasing, calm error messages, avoiding unnecessary punctuation and filler, sentence vs. title case discipline. |
| **Material Design 3 — Content design** (and M2 Writing archive) | https://m3.material.io/foundations/content-design/overview · https://m2.material.io/design/communication/writing.html | Apache 2.0 / CC BY 4.0 (Google). Short quotes and adaptations allowed with attribution. | Scannable microcopy, front-loading the key word in labels and settings, writing for narrow mobile screens, plain-language error recovery. |
| **GOV.UK — Writing to GOV.UK standards & A–Z style guide** | https://guidance.publishing.service.gov.uk/writing-to-gov-uk-standards/tone-of-voice/ · https://guidance.publishing.service.gov.uk/writing-to-gov-uk-standards/style-guides/a-to-z-style-guide/ | Open Government Licence v3.0 (OGL v3.0). Free to quote, adapt and reuse with Crown copyright attribution. | Ruthless plain English, active voice, killing bureaucratic filler ("in order to", "please note"), concrete verbs, writing for stressed or hurried readers. |
| **Mailchimp Content Style Guide** | https://styleguide.mailchimp.com/ (source: https://github.com/mailchimp/content-style-guide) | CC BY-NC 4.0. Free to quote and adapt for non-commercial use with attribution; **do not copy into AGPL/commercial docs** (NC clause is incompatible with AGPL-3.0). Link and paraphrase only. | Clear separation of *voice* (constant) vs. *tone* (adapts to the user's situation, especially errors and destructive actions). |
| **Atlassian Design System — Writing guidelines** | https://atlassian.design/content/writing-guidelines | Proprietary (Atlassian Pty Ltd). Link and paraphrase; do not copy bulk text. | Developer-tool voice: direct, present-tense errors ("state what happened + what to do next"), sentence case everywhere, contractions without being cutesy. |
| **Shopify Polaris — Product content** | https://shopify.dev/docs/api/polaris (content section) | Proprietary / Shopify-only Polaris terms (code/docs restricted to Shopify interop). Link and paraphrase only; never copy assets or bulk text. | Operational admin UIs: action-led buttons, avoiding duplicate headings/captions, 7th-grade plain language for international readers, calm failure guidance. |

### Books

| Book | Author & Publisher | Link / ISBN | Licence / quoting notes | What it is best for |
|---|---|---|---|---|
| ***Microcopy: The Complete Guide*** | Kinneret Yifrah (Nemala) | https://www.microcopybook.com/ | All rights reserved. Cite and summarise; short fair-use quotations only. | Concrete patterns for buttons, confirmations, empty states, form validation and error messages that reduce anxiety without sounding chatty. |
| ***Strategic Writing for UX*** | Torrey Podmajersky (O'Reilly Media, 2019) | ISBN 978-1-492-04939-5 | All rights reserved (O'Reilly). Cite and summarise; short fair-use quotations only. | Turning vague "sound friendly" advice into measurable UI text patterns: clear, concise, purposeful, conversational, and consistent terminology across flows. |

### Recurring patterns across every source

1. **Voice stays steady; tone follows the moment.** A calm, factual voice works
   everywhere; when something fails or can break data, drop any lightness and be
   direct.
2. **Front-load the meaning.** Put the verb or the thing that matters first so
   a reader scanning on a phone catches it in the first two words.
3. **Every error answers two questions:** what happened, and what you can do
   next. Never blame the user, never dump raw internal jargon, and never end in
   a dead end.
4. **Cut filler mercilessly.** Words like "Please", "Successfully", "In order
   to", "Note that", "Just now", "It could not be…" and redundant subtitles add
   noise and make copy sound machine-generated.

---

## 2. Proposed copy checklist for infraternal

Check every new or edited UI string against these eight rules before shipping:

1. **Calm, plain, direct voice.** Write in active voice, present tense, with
   natural contractions ("can't", "isn't", "don't"). Sound like a sharp
   engineer, never a customer-support bot or a press release.
2. **Name the thing; avoid vague pronouns.** Say "This setting", "The host",
   or the host's actual name (`edge-arm`) — never "It", "This", or "That"
   without a clear noun (aligns with `TASTE.md` §4 *Plain, spelled-out wording*).
3. **Use exact verbs on buttons.** A button names the action, not "OK", "Yes",
   or a full sentence: `Remove`, `Keep`, `Reload`, `Try again`, `Copy command`.
   Pair destructive confirms with a safe cancel verb (`Remove` / `Keep`,
   `Forget` / `Keep`, `Revoke` / `Keep`).
4. **Errors say what happened and what to do.** One short sentence for the
   cause (only what is true and observable), followed by the concrete next
   step — or a button that does it (`TASTE.md` §4 *Messages hand you the next
   step*). Never say only "That did not work. Try again."
5. **No filler, hedging, or cheerleading.** Cut "Please", "Sorry", "Oops",
   "Successfully", "Just now", "In order to", "Make sure to", and exclamation
   marks. Success is quiet ("Host connections unlocked", not "Successfully
   unlocked!").
6. **One idea per line; keep confirmations short.** A confirmation card gets a
   short question (`Remove edge-arm?`) and one or two crisp sentences on what
   changes. Multi-step manual fallback instructions belong in Docs or a
   follow-up toast with a copyable command, not a 50-word confirmation block.
7. **Consistent vocabulary.** Follow `CLAUDE.md` and `TASTE.md`:
   - `infraternal agent` for the host daemon; `AI agent` for Claude/Codex/etc.
     (never bare "agent" where it could be ambiguous).
   - `machine` or `host` consistently within a screen; name hosts by their
     hostname, never internal IDs.
   - Sentence case for sentences, descriptions, error messages, and buttons.
8. **No redundant captions or repeated labels.** Do not repeat a heading in a
   row, a button label in its hint, or a switch/choice default ("Default On",
   "Default System") when the control already shows its options (`TASTE.md` §4).

---

## 3. Ten before/after rewrites of real strings in the app

These are verbatim strings currently in `apps/tracer` and `packages/ui`, with
proposed rewrites applying the checklist above. None of these strings have been
changed yet — the owner decides whether to adopt this guide and which rewrites
to apply.

| # | Location | Before (current string) | After (proposed) | Why |
|---|---|---|---|---|
| 1 | `packages/ui/src/setting-row.ts:127` | `"It could not be saved. The old value is still in use."` | `"Couldn't save this setting. Keeping the previous value."` | Replaces vague "It" and passive voice with active, concrete wording. |
| 2 | `apps/tracer/src/canvas/settings-rows/body.on-demand.ts:107` | `"This could not be read just now."` | `"Couldn't load this setting."` | Drops vague "This", passive voice, and filler "just now" (the `Try again` button sits right below it). |
| 3 | `apps/tracer/src/canvas/updates/panel.on-demand.ts:62` | `"That did not work. Try again."` | `"Update action failed. Check your connection and try again."` | Replaces empty filler ("That did not work") with what failed and a concrete check. |
| 4 | `apps/tracer/src/auth.ts:513` | `"The request could not be accepted. Check your details and try again."` | `"Couldn't complete sign-in. Check your passkey or reload the page."` | Replaces bureaucratic "The request could not be accepted" and vague "details" with a real recovery step. |
| 5 | `apps/tracer/src/auth.ts:520` | `"The server sent a response this browser could not use. Try again."` | `"Received an invalid response from the server. Reload the page or update the server."` | Names the concrete next step when a simple retry won't fix a version/proxy mismatch. |
| 6 | `apps/tracer/src/canvas/host-removal.on-demand.ts:32` | `"This request could not be authorised. Refresh the host list and try again."` | `"Your account doesn't have permission for this host. Refresh the host list and try again."` | Drops passive bureaucratic "request could not be authorised" for plain cause + action. |
| 7 | `apps/tracer/src/canvas/host-removal-confirm.ts:39` | `"Forgetting removes this host from the list and stops cleanup retries. Cleanup already sent to the machine may still finish. If the infraternal agent is still installed, sign in to the machine and uninstall it the way it was installed. For a manual install, stop and remove its service unit, then delete its agent files and identity key."` | `"Removes this host from the list and stops uninstall retries. If the infraternal agent is still installed on it, uninstall it on the machine itself."` | Cuts a 54-word confirmation wall down to 25 words; manual service-unit steps belong in Docs, not a compact glass popover. |
| 8 | `apps/tracer/src/canvas/settings-rows/definitions.on-demand.ts:28` | Title: `"Browsers Stay Signed In For"` · Explain: `"Every visit starts the time again; a browser unused this long signs out."` | Title: `"Browser session length"` · Explain: `"Resets on each visit. Idle browsers sign out after this time."` | Drops awkward preposition-ending title and stilted "starts the time again". |
| 9 | `apps/tracer/src/canvas/settings-rows/definitions.on-demand.ts:33` | `"People can open the windows of apps running on their Macs here."` | `"Stream macOS app windows from connected Macs in this browser."` | Replaces clunky phrasing ("windows of apps running on their Macs here") with a crisp, scannable action sentence. |
| 10 | `apps/tracer/src/canvas/mesh/networks-panel.on-demand.ts:130` | `"No machine advertises a network. When one does, it waits here for you to approve it."` | `"No networks shared yet. When a machine offers a subnet, it appears here for approval."` | Replaces jargon ("advertises") and personification ("waits here") with a plain, scannable empty state. |
