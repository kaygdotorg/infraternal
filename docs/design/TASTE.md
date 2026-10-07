# TASTE.md: the owner's design taste, written down

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

This file shapes every piece of UI in infraternal, whoever builds it: the
orchestrator, a fork, or a future design agent. Read it before you touch UI,
and check your work against it before anyone else sees it.

Each rule comes from something the owner actually spotted. The quote is
there so the reason is never lost. **When the owner spots a new annoyance,
add it here the same day**, with the quote, the rule and how to check it.
Never delete a rule. If the owner changes their mind, mark the rule
superseded and say why.

Related decisions: D72 (overlay material), D158–D162 (windows, gestures,
one component per concept, mockup rounds), D171 (Claude builds the UI).
Related documents: `segmented-selection.md` and `toast.md` in this folder.

---

## 1. Restraint ("did being subtle die?")

| Rule | Owner said | Check |
|---|---|---|
| **No rings from mouse, touch or shortcuts.** Focus rings show only during real Tab navigation. They come from the shared helper `packages/ui/src/focus-ring.ts` (`data-focus-ring="on"`), never from bare `:focus` or `:focus-visible`. | "every checkbox has automatic selection rings on checking them?", "no selection rings for mouse actions, no automatic selection rings for keyboard shortcuts" | Click every control: no ring. Open with ⌘K: no ring. Press Escape: no ring. Press Tab: a ring. |
| **Selection is quiet.** A ticked checkbox changes only the checkbox. A selected list row may get a faint tinted fill, but never a border or an outline. | "a selection border shows up everytime i tick something?" | Tick rows and look for borders, outlines or glows. |
| **No fake glass.** No glossy bevels, inner highlights or thick borders on in-page controls (buttons, capsules, segmented controls, close buttons). Glass is only for floating overlays: palette, popovers, tooltips, sheets (D72, D160). | "there's a fake glass spectacle?" | Zoom into every in-page control at 2×: flat fill and at most a 1 px hairline. |
| **No settings inside a flow.** A flow does one job. Configuration (sources, extended info, toggles) lives in Settings, if it exists at all. | "why is 'discovery sources' even a thing?" | List every toggle in a flow and justify each one, or move it out. |
| **One input, not modes.** No tabs to switch between "discovered" and "manual". One field filters, and anything it doesn't recognise becomes the manual path. | "there is no reason for there to be two tabs when there is an input field already?", "anytime the user types something that is not recognized, assume it's a manual flow?" | Count the mode switches. The target is zero. |
| **No invented chrome.** No counters, labels, headers or badges that the decisions don't call for. | "it looks nothing like our existing product's aesthetics", "generic slop" | Every element maps to a decision or to the flow's job. |

## 2. Consistency with the product

| Rule | Owner said | Check |
|---|---|---|
| **Match the existing look exactly.** The deployed core screen, sign-in card and palette are the reference for radii, borders, button styles and sizes, spacing and type. Extend `packages/ui`; never restyle a component locally (D160). | "please, please, please make sure it matches our existing aesthetic" | Put a capture next to the sign-in card and the core screen; nothing may look foreign. |
| **Mockups are built inside the product**, behind a flag, against the mock test double, never as standalone pages. | "I only want mock-ups that actually look like our product" | It runs in `apps/tracer` with `?proto=`. |
| **Monospace everywhere.** The UI font is Geist Mono. Hierarchy comes from weight and size, never from a second family. | "the next mockup you draw, let that be monospace font everywhere (different weight where it applies of course)" | Grep for sans fonts. Never capture with `?ui=sans`. |
| **Weights:** body 450, names and labels 500, titles 600, secondary text 400 in `--fg-2`. Match the sign-in card role for role. | "I think the font weights can be improved" | Compare computed weights with the sign-in card. |
| **One type scale per platform.** Desktop: 13 px body, 12 px secondary, 11 px caption. Touch: 16 / 15 / 13 px. Toasts and tooltips use the same tokens. | "make sure we use the same size text for desktop… the toast looks weird for sure" | Collect the computed font sizes across the product: only scale values. |
| **Platform-sized controls.** Desktop follows the macOS scale: icon buttons about 28 px, rows 28–32 px, sidebar rows about 28 px. Touch follows iOS: 44 px targets. | "the close button is ridiculously big on desktop?", "too much vertical space on the sidebar items?" | Measure the controls at 1440×900 and at 393×852. |
| **Alignment on a 4 px grid**, with one shared left edge for title, input, list and buttons. Nothing touches anything without spacing. | "fonts alignment and sizing is completely fucked up", "proper alignment" | Look at 2× crops of the edges. |
| **Text sizes follow Apple's guidelines.** Phone values are 15–16 px or larger, keys 13–14 px or larger. Contrast is at least 4.5:1, measured over the real background. | "text too small" | Computed sizes plus a pixel-measured contrast check. |
| **Enough icons.** OS marks for hosts, small status icons instead of bare coloured dots, and icons in headers, failures, consent and progress. 16 px on desktop and 18 px on touch, with a 1.5 stroke. | "it still feels too raw! there's not enough icons" | Each row and state has an icon where a native app would have one. |

## 3. Motion

| Rule | Owner said | Check |
|---|---|---|
| **Every state change animates.** Continue, Back, mode changes and success use a short slide plus crossfade (about 200 ms, `cubic-bezier(0.23,1,0.32,1)`), in the direction of travel and interruptible. Reduced motion falls back to opacity only. Keyboard-opened overlays (⌘K) stay instant. | "continue has no animation, back has no animation, changing manual → discovered has no animation" | Sample frames during each transition. |
| **No lag while animating.** Every frame stays under 16 ms. No per-element colour transitions on theme switches: at most one opacity crossfade. | "theme changing could also be way smoother? it's now lagging as it animates" | Record a performance trace of the switch and look at frame times. |
| **Popovers grow from their trigger**, with `transform-origin` at the anchor. | (Apple guidelines and Emil audit, round 3) | Look at the mid-animation frame. |

## 4. Layout and behaviour

| Rule | Owner said | Check |
|---|---|---|
| **Flows live inside a window card**, centred both ways. On success the same window becomes the result. Never open a second window beside the flow. | "the wizard should be within a terminal window only… start the middle (both vertically and horizontally) of a terminal card" | Run the flow from start to success: one window throughout. |
| **Nothing moves without a reason.** A window moves on a sidebar toggle only if it would be covered. | "why does the add host wizard move when sidebar is opened or closed when there's more than enough space?" | Toggle the sidebar with a window open in the centre: no movement. |
| **Nothing modal that doesn't have to be.** On desktop the sidebar docks and never blocks the page. | "if the sidebar is open i can't click on anything?" | Open the sidebar and click every visible control (`elementFromPoint`). |
| **Overlays fit the visual viewport.** Header and actions stay pinned, the middle scrolls, and nothing sits under the keyboard tray or the home indicator. | (rounds 4–5, footer over the key tray) | Phone captures with the content scrolled to the end. |
| **Copy without buttons.** No copy icons next to text: double-tap copies on touch, one click copies on desktop, and an inline tick plus "Copied" confirms it. Keys and values copy separately. | "why is there a copy to clipboard button everywhere?", "the fields key and value should be individually clickable to copy" | Click a key and a value separately; each copies its own text. |
| **Key/value rows:** keys left-aligned, values right-aligned. A long value wraps, still right-aligned. Never an ellipsis. | "make keys left aligned and values right aligned" | Long values at 320 px wide. |
| **No redundant overview chrome.** The canvas is the overview, so there is no strip of every open host at the top. | "there is no reason to show all the open hosts at the top? i can just horizontally scroll the canvas" | The top bar holds only the current session capsule and `+`. |
| **Canvas gestures:** tap activates a window without opening the keyboard, one finger scrolls the terminal, two fingers pan the canvas, pinch changes the font size, and a desktop trackpad pans horizontally anywhere (D159). | "I can't seem to activate a card by directly tapping on it", "horizontally scroll the canvas (which does not work right now btw)" | Touch tests via CDP, plus wheel tests over a terminal and over a gap. |

## 5. Rendering

| Rule | Owner said | Check |
|---|---|---|
| **Crisp text.** Never leave fractional transforms or `will-change` on text ancestors once an animation ends (reset to `transform: none` at rest). The wizard's text must render exactly like the sign-in card's. | "is the text being antialiased by any chance? because monospace doesn't look as clean as the sign in wizard" | Compare 2× crops of the same size and weight side by side. |
| **Terminal metrics come from the font.** Line height uses the font's real height (ascent plus descent), cells are rounded to device pixels, and every glyph sits on its cell. Check the cursor alignment on long lines before any renderer change ships. | "why does terminal text look a bit squished vertically?", "cursor stays 2 characters ahead of where characters appear?" | Cursor-at-end-of-line pixel tests at DPR 1, 2 and 3. |
| **Glass must actually show.** A translucent material over an empty dark area reads as opaque, so judge it over real content. | "still no blur" | Capture over a dense terminal; the content behind is softly visible. |
| **The cursor must not be oversized.** No tall browser caret over the terminal on iOS. | (iOS caret fix) | iPhone capture with the keyboard up. |

## 6. Process (how taste gets enforced)

- **Only the orchestrator builds UI** (D171). Codex jobs never design or restyle UI.
- **Nothing reaches the owner unverified.** Click through every state in a real browser at 1440×900, 393×852 and 375×667, in the ink and paper themes. Read every screenshot, and check this file row by row. A passing test suite is not proof of taste.
- **Mockups come before product** (D162). No new UI ships without mockup rounds and the owner's approval.
- **When the owner spots something, write it here first, then fix it.**
