<!-- Role: the behavioural reference for every toast/notification in infraternal (DECISIONS 141 H16). -->
# Toasts: a dot that opens into the message, burst-aware

Source: Aside's behavioural decode of the MetalForge toast
(https://metalforge.xyz/interactions#component=toast), from the live preview,
the DOM, the public parameters, repeated clicks and Undo, made at the owner's
request (2026-10-07). It is **not copied source**: the downloadable source is
Pro-only. Spring constants, entrance and exit timing, blur, press scale and the
timeout-refresh policy were **not verified**; treat those as ours to tune
against recordings.

## Observed or tested
- Public description: "A dot that opens into the message; a second one rolls
  the count; Undo morphs it in place." A compact dot or status seed expands
  into a rounded message capsule. It is not a rectangular card sliding in.
- **Repeats update one toast.** Twelve rapid clicks gave exactly one status,
  "Message sent ×12". The count rolls, and the width change at 9→10 does not
  shift the whole message abruptly.
- **Undo morphs in place.** Undo on ×12 turned the *same* toast into "Unsent",
  removed the Undo and the count, and emitted
  `undo → {message:'Message sent', count:12}`. That demo event is not proof of
  safe transactional batch reversal in a real app.
- Text is built from per-character spans (for character transitions). Keep
  one readable accessible string; never announce per-letter frames. The
  message and its result use `role=status`.
- Reference settings: a 2.9 s lifetime, 44 px height, fully rounded, a
  shadow, top or bottom placement, optional Undo. Speed, Bounce, Blur
  between states and Press grows are all 1x.
- Reference colours (light: bg #1A1915, text #FFFFFF, dot #1FB257, undo
  #A9BBFF; dark: bg #F2F1EC, text #1A1915, dot #2DC46B, undo #3355FF) only
  indicate contrast. Map them to the theme tokens.

## How infraternal implements it
1. **One persistent toast identity per compatible burst.** Animate dot →
   capsule, the rolling count, and the result morph in place. Retarget from
   the current presentation on interruption. Never remount per count, and
   never scale the text or icons. Cover first appearance, an exit interrupted
   by a new event, resize, RTL and localization, and counts 9→10→99→100.
2. **Group by operation and context identity**, not by message text.
   Different hosts, sessions, entities, severities, actions or undo
   contracts stay separate. Bound the burst window; a fresh burst starts at
   1. One lifecycle owner refreshes the lifetime; no competing timers.
3. **Undo is truthful.**
   - Batch only actions that can really be reversed together; otherwise use
     separate toasts or "Undo last".
   - Disable a repeat Undo while one is pending.
   - Morph to "Undone" only after real success. A failure, refusal or
     partial reversal stays visible and accurate.
   - Never add Undo to irreversible operations. Root promotion has no undo
     (D120/D139).
4. **Loading toasts persist** until the operation resolves, then morph into
   success or error. Long errors stay readable (responsive width and
   wrapping). Routine bursts coalesce; distinct important failures never
   hide inside a count.
5. **Accessibility:** meaningful, bounded live-region announcements with no
   duplicates; keyboard actions and focus-visible; swipe or close; pause on
   hover, focus and hidden tab; safe areas; reduced motion is static or
   short; contrast in every theme.
6. **Library:** if Svelte Sonner is adopted (F1), it owns the queue, stack,
   swipe, dismiss and lifecycle, and we animate an **inner custom renderer**
   (`toast.custom(Component)`, updated by `{id}`), never Sonner's outer
   transform. Check the installed version's API first.
7. **Performance:** no per-frame layout reads, no heavy dependencies, no
   lasting blur, no rAF after settling. Measurements are batched on content,
   size or font changes; observers, timers and state are cleaned up.

## Verify
- 12+ rapid compatible events give one toast with the exact count.
- Mixed contexts give separate toasts.
- Expiry resets the count.
- Entrance and exit interruption.
- Pending, failed and partial Undo; promise rejection.
- Long content; touch, keyboard and reduced motion; all themes; Chromium and
  WebKit.
- Short recordings of the dot expansion, the rolling count and the Undo
  morph, plus perf checks. Screenshots alone do not verify this.
